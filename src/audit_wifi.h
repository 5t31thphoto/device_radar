/**
 * audit_wifi.h — monitor-mode WiFi engine for the Threat Audit.
 *
 * Passive: the radio only listens. Collects
 *   · every AP: crypto, PMF, WPS, TKIP, beacon timestamp (TSF), sequence
 *     numbers, IE fingerprint, hidden names, drone Remote ID payloads
 *   · every transmitter's data traffic (per channel dwell), so streaming
 *     devices — cameras — stand out
 *   · probe requests (what nearby phones reveal about where they've been)
 *   · deauth/disassoc frames, with sequence-number spoof checks
 * The RX callback runs in the WiFi driver task: it only parses and counts.
 */
#pragma once
#include <stdarg.h>

static constexpr int      AUD_MAX_AP    = 96;
static constexpr int      AUD_MAX_STA   = 128;      // power of two (hash table)
static constexpr int      AUD_MAX_PROBE = 32;
static constexpr int      AUD_RING      = 12;       // traffic samples kept per device
static constexpr uint32_t AUD_DWELL_MS  = 220;      // per channel; 1–13 cycle ≈ 2.9 s

// ---------------------------------------------------------------------------
//  Shared definitions
// ---------------------------------------------------------------------------
enum : uint8_t { SEC_OPEN = 0, SEC_WEP, SEC_WPA, SEC_WPA2, SEC_WPA2E, SEC_WPA3, SEC_WPA23 };
static const char* const SEC_NAME[] = {"OPEN", "WEP", "WPA", "WPA2", "WPA2-EAP", "WPA3", "WPA2/3"};

enum : uint8_t { APF_WPS = 1, APF_WPS_LOCKED = 2, APF_PMF_CAP = 4, APF_PMF_REQ = 8, APF_TKIP = 16, APF_RID = 32 };

struct RidInfo {                 // ASTM F3411 / Open Drone ID
    uint8_t  have;               // 1 basic id · 2 location · 4 operator location
    uint8_t  ua_type;
    char     id[21];
    int32_t  lat, lon;           // 1e-7 degrees
    int32_t  op_lat, op_lon;
    int16_t  alt_m;
    uint16_t speed_dms;          // decimetres / s
    uint16_t dir;
};
static const char* const UA_TYPE[] = {"", "aeroplane", "multirotor", "gyroplane", "VTOL", "ornithopter",
                                      "glider", "kite", "balloon", "airship", "parachute", "rocket",
                                      "tethered", "ground obstacle", "other", "other"};

static inline int32_t  le32(const uint8_t* p) { return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24)); }
static inline uint16_t le16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static uint32_t fnv1a(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}
static uint32_t fnv1a_bytes(const uint8_t* b, int n, uint32_t h = 2166136261u) {
    for (int i = 0; i < n; ++i) { h ^= b[i]; h *= 16777619u; }
    return h;
}
static void mac_str(const uint8_t* b, char* out) {   // uppercase, matches WiFi.BSSIDstr()
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
}
static inline bool mac_random(const uint8_t* b) { return b[0] & 0x02; }

// One Open Drone ID message (25 bytes) or a message pack.
static void rid_parse_msg(const uint8_t* m, int n, RidInfo& r, int depth = 0) {
    if (n < 25) return;
    uint8_t t = m[0] >> 4;
    if (t == 0) {                                          // Basic ID
        r.ua_type = m[1] & 0x0F;
        int k = 0;
        for (; k < 20 && m[2 + k]; ++k) r.id[k] = (m[2 + k] >= 0x20 && m[2 + k] < 0x7F) ? (char)m[2 + k] : '?';
        r.id[k] = 0;
        r.have |= 1;
    } else if (t == 1) {                                   // Location / vector
        int32_t lat = le32(m + 5), lon = le32(m + 9);
        if (lat || lon) { r.lat = lat; r.lon = lon; r.have |= 2; }
        uint16_t ga = le16(m + 15), pa = le16(m + 13), a = ga ? ga : pa;
        if (a) r.alt_m = (int16_t)(a * 0.5f - 1000.0f);
        uint8_t sp = m[3];
        r.speed_dms = (m[1] & 1) ? (uint16_t)((sp * 0.75f + 63.75f) * 10) : (uint16_t)(sp * 2.5f);
        r.dir = (uint16_t)(m[2] + ((m[1] & 2) ? 180 : 0));
    } else if (t == 4) {                                   // System: operator position
        int32_t la = le32(m + 2), lo = le32(m + 6);
        if (la || lo) { r.op_lat = la; r.op_lon = lo; r.have |= 4; }
    } else if (t == 0xF && depth == 0) {                   // Message pack
        uint8_t sz = m[1], cnt = m[2];
        if (sz != 25) return;
        for (int k = 0; k < cnt && 3 + (k + 1) * 25 <= n; ++k) rid_parse_msg(m + 3 + k * 25, 25, r, 1);
    }
}

// ---------------------------------------------------------------------------
//  Tables
// ---------------------------------------------------------------------------
enum : uint8_t { FK_BEACON = 1, FK_PRESP, FK_PREQ, FK_DEAUTH };

struct AudFrame {                // callback → main task
    uint8_t  kind;
    uint8_t  a1[6], a2[6], a3[6];
    uint8_t  ch;
    int8_t   rssi;
    uint16_t seq;
    uint8_t  sec, flags;
    uint16_t bint;
    uint32_t ie_fp;
    uint64_t tsf;
    uint32_t rx_us;
    uint8_t  ssid_len;
    char     ssid[33];
    RidInfo  rid;
};

struct AudAP {
    uint8_t  bssid[6];
    char     ssid[33];
    char     revealed[33];
    char     vendor[24];
    char     device_class[32];
    int8_t   rssi, best;
    uint8_t  ch, sec, flags, cat;
    bool     hidden, beaconed;
    uint16_t bint, last_seq;
    bool     seq_valid;
    uint32_t ie_fp;
    uint64_t tsf;
    uint32_t tsf_us;
    uint8_t  tsf_jumps;
    uint32_t tsf_jump_t;
    uint8_t  spoof_deauth;
    uint32_t first_seen, seen;
    uint8_t  names_n;
    uint32_t names[4];
    uint16_t places;
    RidInfo  rid;
};

struct AudSta {                  // any data transmitter (station or AP), keyed by MAC
    uint8_t  mac[6];
    uint8_t  bssid[6];
    volatile uint8_t used;
    uint8_t  ch, is_ap, cat;
    int8_t   rssi, best;
    volatile uint32_t tx_cur, rx_cur;    // bytes this dwell (callback adds, main folds)
    uint32_t tx_tot, rx_tot;
    uint16_t ring[AUD_RING];             // kbps per dwell on its channel
    uint8_t  ring_n, ring_i;
    uint32_t first_seen, seen;
    uint16_t places;
    uint8_t  score;
    bool     vend_done;
    char     vendor[20];
};

struct AudProbe {                // a device sending probe requests
    uint8_t  mac[6];
    int8_t   rssi, best;
    uint32_t first_seen, seen;
    uint16_t places;
    uint8_t  n;
    char     ssids[8][33];
};

static AudAP*    aud_ap    = nullptr;  static int aud_n = 0;
static AudSta*   aud_sta   = nullptr;
static AudProbe* aud_probe = nullptr;  static int aud_probe_n = 0;
static QueueHandle_t aud_q = nullptr;
static volatile bool aud_on = false;

// per-channel counters from the callback
static volatile uint16_t aud_deauth_cnt[14];
static volatile uint16_t aud_frame_cnt[14];
static volatile int8_t   aud_noise_raw[14];
static volatile uint8_t  aud_deauth_bcast[14];

// per-channel picture (main task)
static float    ch_deauth_score[14], ch_deauth_rate[14], ch_activity[14];
static int8_t   ch_noise[14];
static uint8_t  ch_deauth_target[14][6];
static bool     ch_deauth_bcast[14];
static uint32_t aud_deauth_total = 0;
static int      aud_cur_ch = 1;
static volatile int aud_lock_ch = 0;       // >0: stop hopping (hunt / challenge)
static uint32_t aud_hop_t = 0;

// "watch" one transmitter (hunt / challenge)
static volatile bool     aud_watch_on = false;
static uint8_t           aud_watch_mac[6];
static volatile int8_t   aud_watch_rssi = -127;
static volatile uint32_t aud_watch_t = 0;
static volatile uint32_t aud_watch_bytes = 0;

static int sta_slot(const uint8_t* mac, bool insert) {
    uint32_t h = fnv1a_bytes(mac, 6) & (AUD_MAX_STA - 1);
    for (int k = 0; k < 16; ++k) {                   // bounded probing keeps the callback fast
        int i = (int)((h + k) & (AUD_MAX_STA - 1));
        AudSta& s = aud_sta[i];
        if (!s.used) {
            if (!insert) return -1;
            memcpy(s.mac, mac, 6);
            s.first_seen = millis();
            s.best = -127;
            s.used = 1;
            return i;
        }
        if (!memcmp(s.mac, mac, 6)) return i;
    }
    return -1;
}

// ---------------------------------------------------------------------------
//  RX callback (WiFi task)
// ---------------------------------------------------------------------------
static void aud_rx_data(const uint8_t* f, int len, int ch, int8_t rssi) {
    if (len < 24) return;
    uint8_t fl = f[1];
    bool to = fl & 1, from = fl & 2;
    if (to && from) return;                          // mesh backhaul (4-address)
    const uint8_t* ra = f + 4;
    const uint8_t* ta = f + 10;
    const uint8_t* bss = to ? f + 4 : (from ? f + 10 : f + 16);
    if (ta[0] & 1) return;
    uint32_t now = millis();
    int i = sta_slot(ta, true);
    if (i >= 0) {
        AudSta& s = aud_sta[i];
        s.tx_cur += (uint32_t)len;
        s.rssi = rssi;
        if (rssi > s.best) s.best = rssi;
        s.ch = (uint8_t)ch;
        s.is_ap = from ? 1 : 0;
        memcpy(s.bssid, bss, 6);
        s.seen = now;
    }
    if (!(ra[0] & 1)) {
        int j = sta_slot(ra, false);
        if (j >= 0) aud_sta[j].rx_cur += (uint32_t)len;
    }
    if (aud_watch_on && !memcmp(ta, aud_watch_mac, 6)) {
        aud_watch_bytes += (uint32_t)len;
        aud_watch_rssi = rssi;
        aud_watch_t = now;
    }
}

// SENSE (audit_sense.h) taps every frame for ambient-link motion sensing.
static volatile bool aud_sense_on = false;
static void sense_on_frame(const uint8_t* ta, int8_t rssi);

static void aud_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!aud_on) return;
    const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
    int len = (int)p->rx_ctrl.sig_len - 4;           // strip FCS
    const uint8_t* f = p->payload;
    int ch = p->rx_ctrl.channel;
    if (ch < 1 || ch > 13 || len < 10) return;
    int8_t rssi = (int8_t)p->rx_ctrl.rssi;
    aud_frame_cnt[ch]++;
    int8_t nf = (int8_t)p->rx_ctrl.noise_floor;
    if (nf < 0) aud_noise_raw[ch] = nf;

    if (aud_sense_on && len >= 16 && !(f[10] & 1)) sense_on_frame(f + 10, rssi);
    if (type == WIFI_PKT_DATA) { aud_rx_data(f, len, ch, rssi); return; }
    if (type != WIFI_PKT_MGMT || len < 24) return;

    if (aud_watch_on && !memcmp(f + 10, aud_watch_mac, 6)) {
        aud_watch_rssi = rssi;
        aud_watch_t = millis();
    }

    uint8_t st = f[0];
    AudFrame a;
    a.ch = (uint8_t)ch;
    a.rssi = rssi;
    a.seq = (uint16_t)(le16(f + 22) >> 4);
    a.ssid_len = 0; a.ssid[0] = 0;
    a.flags = 0; a.sec = 0; a.ie_fp = 0; a.bint = 0; a.tsf = 0;
    a.rx_us = p->rx_ctrl.timestamp;
    memset(&a.rid, 0, sizeof a.rid);
    memcpy(a.a1, f + 4, 6); memcpy(a.a2, f + 10, 6); memcpy(a.a3, f + 16, 6);

    if (st == 0xC0 || st == 0xA0) {                  // deauth / disassoc
        aud_deauth_cnt[ch]++;
        if (f[4] == 0xFF) aud_deauth_bcast[ch] = 1;
        a.kind = FK_DEAUTH;
        if (aud_q) xQueueSend(aud_q, &a, 0);
        return;
    }
    if (st == 0x40) {                                // probe request
        a.kind = FK_PREQ;
        // IE fingerprint (Vanhoef et al. 2016): which elements, their order and the
        // capability values identify a device model even when its MAC is random.
        uint32_t fp = 2166136261u;
        for (int i = 24; i + 2 <= len;) {
            uint8_t id = f[i], l = f[i + 1];
            const uint8_t* d = f + i + 2;
            if (i + 2 + l > len) break;
            if (id == 0) {
                int n = l > 32 ? 32 : l;
                bool printable = n > 0;
                for (int k = 0; k < n; ++k) if (d[k] < 0x20) { printable = false; break; }
                if (printable) { memcpy(a.ssid, d, n); a.ssid[n] = 0; a.ssid_len = (uint8_t)n; }
            } else if (id != 3) {
                fp ^= id; fp *= 16777619u; fp ^= l; fp *= 16777619u;
                if (id == 1 || id == 50 || id == 45 || id == 127 || id == 191 || id == 107)
                    fp = fnv1a_bytes(d, l, fp);                         // capability contents
                else if (id == 221 && l >= 4) {
                    fp = fnv1a_bytes(d, 4, fp);
                    if (d[0] == 0x00 && d[1] == 0x17 && d[2] == 0xF2) a.flags |= 1;   // Apple vendor IE
                }
            }
            i += 2 + l;
        }
        a.ie_fp = fp;
        if (aud_q) xQueueSend(aud_q, &a, 0);
        return;
    }
    if ((st != 0x80 && st != 0x50) || len < 36) return;

    a.kind = (st == 0x80) ? FK_BEACON : FK_PRESP;
    uint64_t tsf = 0;
    for (int k = 7; k >= 0; --k) tsf = (tsf << 8) | f[24 + k];
    a.tsf = tsf;
    a.bint = le16(f + 32);
    uint16_t cap = le16(f + 34);
    bool privacy = cap & 0x0010;
    bool rsn = false, wpa = false, sae = false, psk = false, eap = false;
    uint32_t fp = 2166136261u;
    int i = 36;
    while (i + 2 <= len) {
        uint8_t id = f[i], l = f[i + 1];
        const uint8_t* d = f + i + 2;
        if (i + 2 + l > len) break;
        fp ^= id; fp *= 16777619u;
        if (id == 0) {
            int n = l > 32 ? 32 : l;
            bool zero = true;
            for (int k = 0; k < n; ++k) if (d[k]) { zero = false; break; }
            if (n && !zero) { memcpy(a.ssid, d, n); a.ssid[n] = 0; a.ssid_len = (uint8_t)n; }
        } else if (id == 3 && l >= 1) {
            if (d[0] >= 1 && d[0] <= 13) a.ch = d[0];
        } else if (id == 48 && l >= 2) {             // RSN
            rsn = true;
            int o = 2;
            if (o + 4 <= l && d[o + 3] == 2) a.flags |= APF_TKIP;     // group cipher TKIP
            o += 4;
            if (o + 2 <= l) {
                int pc = le16(d + o); o += 2;
                for (int k = 0; k < pc && o + 4 <= l; ++k, o += 4) if (d[o + 3] == 2) a.flags |= APF_TKIP;
            }
            if (o + 2 <= l) {
                int ac = le16(d + o); o += 2;
                for (int k = 0; k < ac && o + 4 <= l; ++k, o += 4) {
                    uint8_t t = d[o + 3];
                    if (t == 2 || t == 6) psk = true;
                    else if (t == 8) sae = true;
                    else if (t == 1 || t == 5) eap = true;
                }
            }
            if (o + 2 <= l) {
                uint16_t rc = le16(d + o);
                if (rc & 0x0080) a.flags |= APF_PMF_CAP;
                if (rc & 0x0040) a.flags |= APF_PMF_REQ;
            }
        } else if (id == 221 && l >= 4) {
            fp ^= fnv1a_bytes(d, 4); fp *= 16777619u;
            if (d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2) {
                if (d[3] == 0x01) { wpa = true; a.flags |= APF_TKIP; }   // WPA1 is TKIP-era
                else if (d[3] == 0x04) {                                // WPS
                    a.flags |= APF_WPS;
                    for (int o = 4; o + 4 <= l;) {
                        uint16_t at = (uint16_t)((d[o] << 8) | d[o + 1]);
                        uint16_t al = (uint16_t)((d[o + 2] << 8) | d[o + 3]);
                        if (o + 4 + al > l) break;
                        if (at == 0x1057 && al >= 1 && d[o + 4] == 1) a.flags |= APF_WPS_LOCKED;
                        o += 4 + al;
                    }
                }
            } else if (d[0] == 0xFA && d[1] == 0x0B && d[2] == 0xBC && d[3] == 0x0D && l >= 5 + 25) {
                rid_parse_msg(d + 5, l - 5, a.rid);   // drone Remote ID (OUI, type, counter, pack)
                if (a.rid.have) a.flags |= APF_RID;
            }
        }
        i += 2 + l;
    }
    a.ie_fp = fp;
    if (!privacy)                a.sec = SEC_OPEN;
    else if (rsn && sae)         a.sec = psk ? SEC_WPA23 : SEC_WPA3;
    else if (rsn && eap && !psk) a.sec = SEC_WPA2E;
    else if (rsn)                a.sec = SEC_WPA2;
    else if (wpa)                a.sec = SEC_WPA;
    else                         a.sec = SEC_WEP;
    if (a.sec == SEC_WPA3) a.flags |= APF_PMF_REQ | APF_PMF_CAP;
    if (aud_q) xQueueSend(aud_q, &a, 0);
}

// ---------------------------------------------------------------------------
//  Radio control
// ---------------------------------------------------------------------------
static void aud_set_channel(int c) {
    aud_cur_ch = c;
    esp_wifi_set_channel((uint8_t)c, WIFI_SECOND_CHAN_NONE);
    aud_hop_t = millis();
}

static void aud_wifi_start() {
    ble_stop_scan();
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(&aud_rx_cb);
    aud_on = true;
    esp_wifi_set_promiscuous(true);
    aud_set_channel(aud_lock_ch > 0 ? aud_lock_ch : 1);
}

static void aud_wifi_stop() {
    aud_on = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    delay(20);                                        // let an in-flight callback finish
    wifi_off();
    if (aud_q) xQueueReset(aud_q);
}

// ---------------------------------------------------------------------------
//  Main-task processing
// ---------------------------------------------------------------------------
static const char* aud_name(const AudAP& a) {
    if (a.ssid[0]) return a.ssid;
    if (a.revealed[0]) return a.revealed;
    return "<hidden>";
}

static uint8_t aud_auth_mode(uint8_t sec) {           // for wifi_classify()
    switch (sec) {
        case SEC_OPEN:  return WIFI_AUTH_OPEN;
        case SEC_WEP:   return WIFI_AUTH_WEP;
        case SEC_WPA:   return WIFI_AUTH_WPA_PSK;
        case SEC_WPA2E: return WIFI_AUTH_WPA2_ENTERPRISE;
#ifdef WIFI_AUTH_WPA3_PSK
        case SEC_WPA3:  return WIFI_AUTH_WPA3_PSK;
#endif
#ifdef WIFI_AUTH_WPA2_WPA3_PSK
        case SEC_WPA23: return WIFI_AUTH_WPA2_WPA3_PSK;
#endif
        default:        return WIFI_AUTH_WPA2_PSK;
    }
}

static void aud_classify(AudAP& a) {
    WifiIdentity w;
    memset(&w, 0, sizeof w);
    mac_str(a.bssid, w.bssid);
    strncpy(w.ssid, a.ssid[0] ? a.ssid : a.revealed, sizeof(w.ssid) - 1);
    strncpy(w.vendor, a.vendor, sizeof(w.vendor) - 1);
    w.encrypt = aud_auth_mode(a.sec);
    w.channel = (int8_t)a.ch;
    w.hidden = a.hidden;
    wifi_classify(w);
    if (a.cat == CAT_CAMERA && !strstr(w.device_class, "amera")) snprintf(w.device_class, sizeof(w.device_class), "%s camera", a.vendor);
    if (a.cat == CAT_LPR)     strncpy(w.device_class, "Flock Safety camera", sizeof(w.device_class) - 1);
    if (a.cat == CAT_POLICE)  snprintf(w.device_class, sizeof(w.device_class), "%s (public safety)", a.vendor);
    if (a.cat == CAT_DRONE)   strncpy(w.device_class, "Drone / controller", sizeof(w.device_class) - 1);
    if (a.cat == CAT_VEHICLE) strncpy(w.device_class, "Vehicle router", sizeof(w.device_class) - 1);
    if (a.cat == CAT_ATTACK)  snprintf(w.device_class, sizeof(w.device_class), "%s", a.vendor);
    if (a.cat == CAT_NONE && ssid_cam_hint(w.ssid) && !strstr(w.device_class, "amera"))
        strncpy(w.device_class, "Camera-style hotspot", sizeof(w.device_class) - 1);
    copy_ascii(a.device_class, w.device_class, sizeof(a.device_class));
}

static int aud_find_ap(const uint8_t* b) {
    for (int i = 0; i < aud_n; ++i) if (!memcmp(aud_ap[i].bssid, b, 6)) return i;
    return -1;
}

static int aud_new_ap(const uint8_t* b) {
    int i;
    if (aud_n < AUD_MAX_AP) i = aud_n++;
    else {
        i = 0;
        for (int k = 1; k < aud_n; ++k) if (aud_ap[k].seen < aud_ap[i].seen) i = k;
    }
    AudAP& a = aud_ap[i];
    memset(&a, 0, sizeof a);
    memcpy(a.bssid, b, 6);
    a.hidden = true;
    a.best = -127;
    a.first_seen = millis();
    intel_vendor(b, a.vendor, sizeof a.vendor, &a.cat);
    return i;
}

static int aud_find_probe(const uint8_t* m, bool insert) {
    for (int i = 0; i < aud_probe_n; ++i) if (!memcmp(aud_probe[i].mac, m, 6)) return i;
    if (!insert) return -1;
    int i;
    if (aud_probe_n < AUD_MAX_PROBE) i = aud_probe_n++;
    else {
        i = 0;
        for (int k = 1; k < aud_probe_n; ++k) if (aud_probe[k].seen < aud_probe[i].seen) i = k;
    }
    AudProbe& p = aud_probe[i];
    memset(&p, 0, sizeof p);
    memcpy(p.mac, m, 6);
    p.best = -127;
    p.first_seen = millis();
    return i;
}

static void aud_handle_ap_frame(const AudFrame& f) {
    int i = aud_find_ap(f.a3);
    if (i < 0) i = aud_new_ap(f.a3);
    AudAP& a = aud_ap[i];
    bool reclass = false;
    if (f.kind == FK_BEACON) {
        a.beaconed = true;
        bool hid = (f.ssid_len == 0);
        if (hid != a.hidden) reclass = true;
        a.hidden = hid;
        if (!hid && strcmp(a.ssid, f.ssid)) { copy_ascii(a.ssid, f.ssid, sizeof a.ssid); reclass = true; }
        if (a.sec != f.sec) reclass = true;
        a.sec = f.sec;
        a.ch = f.ch;
        a.flags = (uint8_t)((a.flags & APF_RID) | f.flags);
        a.bint = f.bint;
        a.ie_fp = f.ie_fp;
        // TSF continuity: two radios sharing one BSSID can't keep one clock
        if (a.tsf_us) {
            int64_t expect = (int64_t)a.tsf + (int64_t)(uint32_t)(f.rx_us - a.tsf_us);
            int64_t d = (int64_t)f.tsf - expect;
            if (d > 200000 || d < -200000) { a.tsf_jumps++; a.tsf_jump_t = millis(); }
        }
        a.tsf = f.tsf;
        a.tsf_us = f.rx_us;
    } else {
        if (f.ssid_len && a.hidden && strcmp(a.revealed, f.ssid)) {
            copy_ascii(a.revealed, f.ssid, sizeof a.revealed);
            reclass = true;
        }
        if (!a.beaconed) {
            a.sec = f.sec; a.ch = f.ch; a.flags = f.flags;
            if (f.ssid_len && !a.ssid[0]) { copy_ascii(a.ssid, f.ssid, sizeof a.ssid); a.hidden = false; reclass = true; }
        }
    }
    a.last_seq = f.seq;
    a.seq_valid = true;
    if (f.flags & APF_RID) {
        RidInfo& r = a.rid;
        if (f.rid.have & 1) { strncpy(r.id, f.rid.id, sizeof r.id); r.ua_type = f.rid.ua_type; }
        if (f.rid.have & 2) { r.lat = f.rid.lat; r.lon = f.rid.lon; r.alt_m = f.rid.alt_m; r.speed_dms = f.rid.speed_dms; r.dir = f.rid.dir; }
        if (f.rid.have & 4) { r.op_lat = f.rid.op_lat; r.op_lon = f.rid.op_lon; }
        r.have |= f.rid.have;
        a.flags |= APF_RID;
    }
    if (f.ssid_len) {
        uint32_t h = fnv1a(f.ssid);
        bool known = false;
        int stored = a.names_n < 4 ? a.names_n : 4;
        for (int k = 0; k < stored; ++k) if (a.names[k] == h) { known = true; break; }
        if (!known) {
            if (a.names_n < 4) a.names[a.names_n] = h;
            if (a.names_n < 255) a.names_n++;
        }
    }
    a.rssi = f.rssi;
    if (f.rssi > a.best) a.best = f.rssi;
    a.seen = millis();
    if (reclass || !a.device_class[0]) aud_classify(a);
}

static void aud_handle_deauth(const AudFrame& f) {
    // Claimed sender is usually the AP. A real AP's management frames share one
    // sequence counter with its beacons; a forger's counter won't line up.
    int i = aud_find_ap(f.a2);
    if (i < 0) i = aud_find_ap(f.a3);
    if (i >= 0 && aud_ap[i].seq_valid) {
        uint16_t diff = (uint16_t)((f.seq - aud_ap[i].last_seq) & 0x0FFF);
        if (diff > 500 && diff < 3596 && aud_ap[i].spoof_deauth < 255) aud_ap[i].spoof_deauth++;
    }
    if (f.ch >= 1 && f.ch <= 13) memcpy(ch_deauth_target[f.ch], f.a3, 6);
}

// Probe senders clustered into physical devices despite MAC randomisation:
// same IE fingerprint + sequence number continuing from where the last MAC
// stopped (frame counters survive MAC changes on most chipsets).
struct ProbeDev { uint32_t fp; uint16_t seq; uint32_t t; int8_t rssi; bool apple; };
static constexpr int AUD_MAX_PDEV = 128;
static ProbeDev aud_pdev[AUD_MAX_PDEV];
static int      aud_pdev_n = 0;

static void pdev_observe(uint32_t fp, uint16_t seq, int8_t rssi, bool apple) {
    uint32_t now = millis();
    int hit = -1;
    for (int i = 0; i < aud_pdev_n; ++i) {
        ProbeDev& d = aud_pdev[i];
        if (d.fp != fp || now - d.t > 60000) continue;
        uint16_t ds = (uint16_t)((seq - d.seq) & 0x0FFF);
        if (ds <= 64) { hit = i; break; }
    }
    if (hit < 0) {
        if (aud_pdev_n < AUD_MAX_PDEV) hit = aud_pdev_n++;
        else { hit = 0; for (int i = 1; i < aud_pdev_n; ++i) if (aud_pdev[i].t < aud_pdev[hit].t) hit = i; }
        aud_pdev[hit].rssi = rssi;
    }
    ProbeDev& d = aud_pdev[hit];
    d.fp = fp; d.seq = seq; d.t = now; d.apple = apple;
    d.rssi = (int8_t)std::max<int>(rssi, d.rssi - 3);     // slow-decaying peak
}

static void aud_handle_probe(const AudFrame& f) {
    pdev_observe(f.ie_fp, f.seq, f.rssi, f.flags & 1);
    int i = aud_find_probe(f.a2, true);
    AudProbe& p = aud_probe[i];
    p.rssi = f.rssi;
    if (f.rssi > p.best) p.best = f.rssi;
    p.seen = millis();
    if (!f.ssid_len) return;
    for (int k = 0; k < p.n; ++k) if (!strcmp(p.ssids[k], f.ssid)) return;
    if (p.n < 8) copy_ascii(p.ssids[p.n++], f.ssid, sizeof p.ssids[0]);
}

static void aud_wifi_drain() {
    AudFrame f;
    int budget = 96;
    while (budget-- > 0 && aud_q && xQueueReceive(aud_q, &f, 0) == pdTRUE) {
        switch (f.kind) {
            case FK_BEACON:
            case FK_PRESP:  aud_handle_ap_frame(f); break;
            case FK_DEAUTH: aud_handle_deauth(f); break;
            case FK_PREQ:   aud_handle_probe(f); break;
        }
    }
}

// Leaving channel c: fold that dwell's counters into the long-term picture.
static void aud_close_dwell(int c, uint32_t dwell_ms) {
    if (c < 1 || c > 13 || dwell_ms == 0) return;
    uint16_t n = aud_deauth_cnt[c];  aud_deauth_cnt[c] = 0;
    uint16_t fr = aud_frame_cnt[c];  aud_frame_cnt[c] = 0;
    float dt = dwell_ms / 1000.0f;
    ch_deauth_score[c] = ch_deauth_score[c] * 0.8f + n;
    ch_deauth_rate[c]  = std::max(n / dt, ch_deauth_rate[c] * 0.8f);
    ch_deauth_bcast[c] = aud_deauth_bcast[c] || (ch_deauth_bcast[c] && ch_deauth_score[c] >= 1.0f);
    aud_deauth_bcast[c] = 0;
    ch_activity[c] = ch_activity[c] * 0.6f + 0.4f * (fr / dt);
    if (aud_noise_raw[c] < 0) ch_noise[c] = aud_noise_raw[c];
    aud_deauth_total += n;

    for (int i = 0; i < AUD_MAX_STA; ++i) {
        AudSta& s = aud_sta[i];
        if (!s.used || s.ch != c) continue;
        uint32_t tx = s.tx_cur, rx = s.rx_cur;
        s.tx_cur = 0; s.rx_cur = 0;
        s.tx_tot += tx; s.rx_tot += rx;
        uint32_t kbps = tx * 8 / dwell_ms;               // bits per ms == kbit/s
        s.ring[s.ring_i] = (uint16_t)std::min<uint32_t>(kbps, 65535);
        s.ring_i = (uint8_t)((s.ring_i + 1) % AUD_RING);
        if (s.ring_n < AUD_RING) s.ring_n++;
    }
}

static uint16_t sta_median_kbps(const AudSta& s) {
    if (!s.ring_n) return 0;
    uint16_t v[AUD_RING];
    for (int i = 0; i < s.ring_n; ++i) v[i] = s.ring[i];
    std::sort(v, v + s.ring_n);
    return v[s.ring_n / 2];
}
