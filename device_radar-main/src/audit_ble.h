/**
 * audit_ble.h — passive BLE engine for the Threat Audit.
 *
 * Runs a PASSIVE scan (no scan requests sent) in its own task alongside WiFi
 * monitor mode. Recognises:
 *   · Apple Find My accessories in "separated" (lost) mode — AirTags & clones
 *   · Google Find My Device tags, including unwanted-tracking-protection mode
 *   · Samsung SmartTag, Tile
 *   · drone Remote ID over Bluetooth (ASTM F3411, service 0xFFFA)
 *   · Flipper Zero, Apple pop-up spam floods
 *   · police / camera gear by name, class and maker prefix
 */
#pragma once

enum : uint8_t {
    BK_NONE = 0, BK_FINDMY_SEP, BK_FMDN, BK_FMDN_UTP, BK_SMARTTAG, BK_TILE,
    BK_RID, BK_FLIPPER, BK_POLICE, BK_CAMERA, BK_SPAM, BK_GLASSES, BK_TESLA
};
static const char* const BK_NAME[] = {"", "Find My tag (lost mode)", "Google Find My tag",
                                      "Google tag (anti-stalk mode)", "Samsung SmartTag", "Tile",
                                      "drone Remote ID", "Flipper Zero", "police / LPR gear",
                                      "camera", "BLE spam", "camera glasses", "Tesla (Sentry cams)"};
static inline bool bk_is_tracker(uint8_t k) { return k >= BK_FINDMY_SEP && k <= BK_TILE; }

struct AudBle {                 // BLE task → main task
    char    addr[18];
    uint8_t kind;
    int8_t  rssi;
    uint8_t status;             // Find My status byte (battery in bits 6-7)
    uint8_t spam_n;
    char    name[20];
    char    cls[28];
    RidInfo rid;
};

struct AudTrk {
    char     addr[18];
    uint8_t  kind;
    int8_t   rssi, best;
    uint8_t  status;
    uint32_t first_seen, seen;
    uint16_t places;
    uint16_t sightings;
    char     name[20];
    char     cls[28];
    RidInfo  rid;
};

static constexpr int AUD_MAX_TRK = 48;
static AudTrk*       aud_trk = nullptr;
static int           aud_trk_n = 0;
static QueueHandle_t aud_bq = nullptr;
static volatile bool aud_ble_run = false, aud_ble_alive = false;
// Radio schedule (see aud_sched in audit_analysis.h): the BLE task scans only
// while aud_ble_window is set, then hands the radio back by clearing it.
static volatile bool aud_ble_window = false;
static volatile bool aud_ble_continuous = false;     // BLE fox hunt: keep the window open
static bool          aud_ble_ok = false;
static uint8_t       aud_spam_n = 0;
static uint32_t      aud_spam_t = 0;

// fox-hunt watch on one BLE address (fed per advert by the callback)
static volatile bool     aud_bwatch_on = false;
static char              aud_bwatch_addr[18];
static volatile int8_t   aud_bwatch_rssi = -127;
static volatile uint32_t aud_bwatch_t = 0;

class AudBleCallback : public BLEAdvertisedDeviceCallbacks {
public:
    void onResult(BLEAdvertisedDevice d) override {
        if (!aud_bwatch_on) return;
        auto a = d.getAddress().toString();
        if (!strcasecmp(a.c_str(), aud_bwatch_addr)) {
            aud_bwatch_rssi = (int8_t)d.getRSSI();
            aud_bwatch_t = millis();
        }
    }
};
static AudBleCallback aud_ble_cb;

// Walk the raw advertisement for tracker / Remote ID / spam signatures.
// Apple Continuity "Nearby Info" emitters seen recently (people census).
static constexpr int AUD_MAX_APPLE = 96;
static volatile uint32_t aud_apple_h[AUD_MAX_APPLE];
static volatile uint32_t aud_apple_t[AUD_MAX_APPLE];
static volatile int8_t   aud_apple_r[AUD_MAX_APPLE];

static void apple_census(const char* addr, int8_t rssi) {
    uint32_t h = fnv1a(addr), now = millis();
    int slot = -1, oldest = 0;
    for (int i = 0; i < AUD_MAX_APPLE; ++i) {
        if (aud_apple_h[i] == h) { slot = i; break; }
        if (aud_apple_t[i] < aud_apple_t[oldest]) oldest = i;
    }
    if (slot < 0) slot = oldest;
    aud_apple_h[slot] = h; aud_apple_t[slot] = now; aud_apple_r[slot] = rssi;
}

static bool tesla_name(const char* n) {          // "S" + 16 hex (SHA1 of VIN) + role letter
    if (strlen(n) != 18 || n[0] != 'S') return false;
    for (int i = 1; i < 17; ++i) if (!isxdigit((unsigned char)n[i])) return false;
    return isalpha((unsigned char)n[17]);
}

static uint8_t ble_signature(const uint8_t* p, size_t n, AudBle& out, bool& apple_popup, bool* nearby_info = nullptr) {
    uint8_t kind = BK_NONE;
    apple_popup = false;
    if (nearby_info) *nearby_info = false;
    static const uint8_t kTeslaUuid[16] = {0x74, 0x27, 0x8B, 0xDA, 0xB6, 0x44, 0x45, 0x20,
                                           0x8F, 0x0C, 0x72, 0x0E, 0xAF, 0x05, 0x99, 0x35};
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = p[i];
        if (!len || i + 1 + len > n) break;
        uint8_t t = p[i + 1];
        const uint8_t* d = p + i + 2;
        uint8_t dl = len - 1;
        if (t == 0xFF && dl >= 3 && d[0] == 0x4C && d[1] == 0x00) {             // Apple
            if (d[2] == 0x12 && dl >= 5 && d[3] == 0x19) {                      // offline finding, full key
                kind = BK_FINDMY_SEP;
                out.status = d[4];
            }
            if (d[2] == 0x07 || d[2] == 0x0F) apple_popup = true;               // proximity pairing / nearby action
            if (nearby_info) for (uint8_t o = 2; o + 1 < dl; o += 2 + d[o + 1])  // walk Continuity TLVs
                if (d[o] == 0x10) { *nearby_info = true; break; }
            if (d[2] == 0x02 && dl >= 20 && !memcmp(d + 4, kTeslaUuid, 16)) kind = BK_TESLA;   // Tesla PhoneKey iBeacon
        } else if (t == 0xFF && dl >= 2 && kind == BK_NONE) {                   // camera-glasses makers
            uint16_t cid = (uint16_t)(d[0] | (d[1] << 8));
            if (cid == 0x01AB || cid == 0x058E || cid == 0x0D53 || cid == 0x03C2) kind = BK_GLASSES;
        } else if (t == 0x16 && dl >= 3) {                                      // 16-bit service data
            uint16_t u = (uint16_t)(d[0] | (d[1] << 8));
            if (u == 0xFEAA && (d[2] == 0x40 || d[2] == 0x41)) kind = d[2] == 0x41 ? BK_FMDN_UTP : BK_FMDN;
            else if (u == 0xFD5A && kind == BK_NONE) kind = BK_SMARTTAG;
            else if (u == 0xFEED && kind == BK_NONE) kind = BK_TILE;
            else if (u == 0xFFFA && d[2] == 0x0D && dl >= 4 + 25) {             // Remote ID: app code, counter, msg
                rid_parse_msg(d + 4, dl - 4, out.rid);
                if (out.rid.have) kind = BK_RID;
            }
        } else if ((t == 0x02 || t == 0x03) && kind == BK_NONE) {               // 16-bit UUID lists
            for (uint8_t o = 0; o + 1 < dl; o += 2) {
                uint16_t u = (uint16_t)(d[o] | (d[o + 1] << 8));
                if (u == 0xFEED) kind = BK_TILE;
                else if (u == 0xFD5A) kind = BK_SMARTTAG;
            }
        }
        i += (size_t)len + 1;
    }
    return kind;
}

static void aud_ble_worker(void*) {
    while (aud_ble_run) {
        if (!aud_ble_window) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }
        auto res_v = ble_scan->start(aud_ble_continuous ? 1 : 2, false);
        auto& res = scan_results(res_v);
        int n = res.getCount();
        int popups = 0;
        for (int i = 0; i < n && aud_ble_run; ++i) {
            BLEAdvertisedDevice d = res.getDevice(i);
            AudBle b;
            memset(&b, 0, sizeof b);
            auto a = d.getAddress().toString();
            strncpy(b.addr, a.c_str(), sizeof(b.addr) - 1);
            b.rssi = (int8_t)d.getRSSI();
            bool popup = false, nearby = false;
            if (d.getPayload() && d.getPayloadLength())
                b.kind = ble_signature(d.getPayload(), d.getPayloadLength(), b, popup, &nearby);
            uint8_t at = d.getAddressType();
            bool rnd = (at == 1 || at == 3);
            if (popup && rnd) popups++;
            if (nearby) apple_census(b.addr, b.rssi);

            if (aud_bwatch_on && !strcasecmp(b.addr, aud_bwatch_addr)) {
                aud_bwatch_rssi = b.rssi;
                aud_bwatch_t = millis();
            }

            // names, classes and maker prefixes for everything else of interest
            BleIdentity idn;
            ble_identify(d, idn);
            copy_ascii(b.name, strcmp(idn.name, "(no name)") ? idn.name : "", sizeof b.name);
            copy_ascii(b.cls, idn.device_class, sizeof b.cls);
            if (b.kind == BK_NONE) {
                const char* c = idn.device_class;
                if (!strncmp(idn.name, "Flipper ", 8)) b.kind = BK_FLIPPER;
                else if (tesla_name(idn.name)) b.kind = BK_TESLA;
                else if (strstr(c, "Axon") || strstr(c, "Flock")) b.kind = BK_POLICE;
                else if (strstr(c, "amera") || strstr(c, "Ring")) b.kind = BK_CAMERA;
                else if (strstr(c, "AirTag") || strstr(c, "Tile") || strstr(c, "SmartTag") ||
                         strstr(c, "Tracker") || strstr(c, "tracker")) {
                    // tracker family seen by name/class only (not lost-mode)
                    b.kind = strstr(c, "Tile") ? BK_TILE : strstr(c, "Samsung") ? BK_SMARTTAG : BK_NONE;
                }
                if (b.kind == BK_NONE && !rnd) {
                    uint8_t mac[6];
                    unsigned v[6];
                    if (sscanf(b.addr, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) {
                        for (int k = 0; k < 6; ++k) mac[k] = (uint8_t)v[k];
                        IntelHit h;
                        if (intel_lookup(mac, h)) {
                            if (h.cat == CAT_POLICE || h.cat == CAT_LPR) b.kind = BK_POLICE;
                            else if (h.cat == CAT_CAMERA) b.kind = BK_CAMERA;
                            else if (h.cat == CAT_ATTACK) b.kind = BK_FLIPPER;
                        }
                    }
                }
            }
            if (b.kind != BK_NONE && aud_bq) xQueueSend(aud_bq, &b, 0);
        }
        if (popups >= 12 && aud_bq) {
            AudBle s;
            memset(&s, 0, sizeof s);
            s.kind = BK_SPAM;
            s.spam_n = (uint8_t)std::min(popups, 255);
            xQueueSend(aud_bq, &s, 0);
        }
        ble_scan->clearResults();
        if (!aud_ble_continuous) aud_ble_window = false;      // radio back to WiFi
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    aud_ble_alive = false;
    vTaskDelete(nullptr);
}

static void aud_ble_start() {
    aud_ble_ok = false;
    if (!aud_bq) aud_bq = xQueueCreate(48, sizeof(AudBle));
    if (!aud_bq) return;
    if (!ble_ready) {
        if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) < 70000) {
            Serial.println("audit: BLE skipped (low internal RAM)");
            return;
        }
        BLEDevice::init("");
        ble_scan = BLEDevice::getScan();
        if (!ble_scan) return;
        ble_ready = true;
    }
    ble_scan->setAdvertisedDeviceCallbacks(&aud_ble_cb, false);
    ble_scan->setActiveScan(false);           // passive: listen only
    ble_scan->setInterval(100);
    ble_scan->setWindow(95);
    ble_scan->clearResults();
    aud_ble_window = false;
    aud_ble_continuous = false;
    aud_ble_run = true;
    aud_ble_alive = true;
    xTaskCreatePinnedToCore(aud_ble_worker, "audble", 10240, nullptr, 1, nullptr, 0);
    aud_ble_ok = true;
}

static void aud_ble_stop() {
    if (!aud_ble_ok) return;
    aud_ble_run = false;
    uint32_t t0 = millis();
    while (aud_ble_alive && millis() - t0 < 4000) delay(20);
    if (ble_scan) {
        ble_scan->stop();
        ble_scan->clearResults();
        ble_scan->setAdvertisedDeviceCallbacks(&ble_cb, false);   // hand back to the radar
    }
    aud_bwatch_on = false;
    aud_ble_ok = false;
}

// Fox hunt on a BLE target: report every advert, not one per scan window.
static void aud_ble_watch(const char* addr, bool on) {
    if (on) {
        strncpy(aud_bwatch_addr, addr, sizeof(aud_bwatch_addr) - 1);
        aud_bwatch_addr[sizeof(aud_bwatch_addr) - 1] = 0;
        aud_bwatch_rssi = -127;
        aud_bwatch_t = 0;
    }
    aud_bwatch_on = on;
    if (ble_scan && aud_ble_ok) ble_scan->setAdvertisedDeviceCallbacks(&aud_ble_cb, on);
    aud_ble_continuous = on;
}

static int aud_find_trk(const char* addr, bool insert) {
    for (int i = 0; i < aud_trk_n; ++i) if (!strcasecmp(aud_trk[i].addr, addr)) return i;
    if (!insert) return -1;
    int i;
    if (aud_trk_n < AUD_MAX_TRK) i = aud_trk_n++;
    else {
        i = 0;
        for (int k = 1; k < aud_trk_n; ++k) if (aud_trk[k].seen < aud_trk[i].seen) i = k;
    }
    AudTrk& t = aud_trk[i];
    memset(&t, 0, sizeof t);
    strncpy(t.addr, addr, sizeof(t.addr) - 1);
    t.best = -127;
    t.first_seen = millis();
    return i;
}

static void aud_ble_drain() {
    AudBle b;
    int budget = 32;
    while (budget-- > 0 && aud_bq && xQueueReceive(aud_bq, &b, 0) == pdTRUE) {
        if (b.kind == BK_SPAM) { aud_spam_n = b.spam_n; aud_spam_t = millis(); continue; }
        int i = aud_find_trk(b.addr, true);
        AudTrk& t = aud_trk[i];
        // a stronger signature wins (e.g. name-only Tile → lost-mode Find My)
        if (b.kind == BK_RID || b.kind == BK_FINDMY_SEP || b.kind == BK_FMDN_UTP || b.kind == BK_GLASSES ||
            b.kind == BK_TESLA || t.kind == BK_NONE) t.kind = b.kind;
        t.rssi = b.rssi;
        if (b.rssi > t.best) t.best = b.rssi;
        t.status = b.status;
        t.seen = millis();
        if (t.sightings < 65535) t.sightings++;
        if (b.name[0]) strncpy(t.name, b.name, sizeof t.name);
        if (b.cls[0])  strncpy(t.cls, b.cls, sizeof t.cls);
        if (b.rid.have) {
            if (b.rid.have & 1) { strncpy(t.rid.id, b.rid.id, sizeof t.rid.id); t.rid.ua_type = b.rid.ua_type; }
            if (b.rid.have & 2) { t.rid.lat = b.rid.lat; t.rid.lon = b.rid.lon; t.rid.alt_m = b.rid.alt_m;
                                  t.rid.speed_dms = b.rid.speed_dms; t.rid.dir = b.rid.dir; }
            if (b.rid.have & 4) { t.rid.op_lat = b.rid.op_lat; t.rid.op_lon = b.rid.op_lon; }
            t.rid.have |= b.rid.have;
        }
    }
}
