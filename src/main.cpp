/**
 * DeviceRadar — M5Stack Core2
 *
 * Standalone WiFi + BLE rotational radar.
 * Ported from the Fox Voice Companion radar tools.
 * Mantis theme · M5Unified · single merged binary.
 *
 * Controls:
 *   Menu   – tap an item to start it · BtnA start highlighted · BtnB next · hold BtnC power off
 *   Radar  – BtnA rescan · BtnB device list · BtnC (or hold A) exit · tap a dot for its details
 *   List   – tap a row to select it, tap it again for details · swipe to page
 *            BtnA up · BtnB down · hold A details · BtnC or "< back" to return
 */

#include <M5Unified.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <esp_heap_caps.h>
#include <SPI.h>
#include <SD.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <math.h>
#include <string.h>
#include <string>
#include <algorithm>
#include "mantis_sprite.h"
#include "ble_id.h"
#include "wifi_id.h"

// ---------------------------------------------------------------------------
//  Tuning
// ---------------------------------------------------------------------------
// Direction of the gyro heading. If dots come out mirrored (a source on your
// right is drawn on the left), or you had to turn counter-clockwise to keep the
// green needle on the red one during the sweep, change this to -1.0f.
static constexpr float YAW_SIGN = 1.0f;

// WiFi is scanned one channel at a time so every AP gets the heading from the
// ~150 ms it was actually heard in, instead of a 5 s all-channel sweep.
static constexpr uint32_t WIFI_MS_PER_CHANNEL = 150;
static constexpr int      WIFI_MAX_CHANNEL    = 13;

// ---------------------------------------------------------------------------
//  Mantis theme colours (RGB565)
//  #007373 teal · #5d005d purple · lime · dark grey
// ---------------------------------------------------------------------------
static constexpr uint16_t COL_BG       = 0x18C3;   // #1a1a1a dark grey
static constexpr uint16_t COL_PANEL    = 0x2965;   // #2d2d2d mid grey
static constexpr uint16_t COL_TEAL     = 0x038E;   // #007373
static constexpr uint16_t COL_PURPLE   = 0x580B;   // #5d005d
static constexpr uint16_t COL_LIME     = 0xB7E0;   // lime green
static constexpr uint16_t COL_GRID     = 0x31A6;
static constexpr uint16_t COL_RING     = 0x4208;
static constexpr uint16_t COL_RED      = 0xF800;
static constexpr uint16_t COL_DIM      = 0x8410;
static constexpr uint16_t COL_HINT     = 0x9CF3;
static constexpr uint16_t COL_TEXT     = 0xEF5D;

static constexpr int RADAR_SOURCES = 32;
static constexpr int RADAR_BINS    = 72;          // 5° per bin

static constexpr int SCREEN_W = 320, SCREEN_H = 240;
static int CX = 160, CY = 120, R = 95;

// ---------------------------------------------------------------------------
//  Small helpers
// ---------------------------------------------------------------------------
// Copy a name into a fixed buffer as plain ASCII. The built-in fonts only cover
// ASCII, so UTF-8 SSIDs / BLE names (emoji, accents) would otherwise draw as junk.
static void copy_ascii(char* dst, const char* src, size_t n) {
    if (!n) return;
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < n; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c >= 0x80) {
            if ((c & 0xC0) == 0x80) continue;   // UTF-8 continuation byte
            dst[j++] = '?';
        } else if (c < 0x20) {
            dst[j++] = ' ';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = 0;
}

static void log_heap(const char* tag) {
    Serial.printf("[%s] heap: %u internal, %u psram\n", tag,
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}

// ---------------------------------------------------------------------------
//  Radar data
// ---------------------------------------------------------------------------
struct RadarSource {
    char     id[18];
    char     name[28];
    int8_t   rssi[RADAR_BINS];   // smoothed RSSI heard while facing each 5° bin
    uint8_t  hits[RADAR_BINS];   // samples per bin (presence only — not used as a weight)
    int      strongest;
    uint32_t seen;
    // identification snapshot (BLE forensic / WiFi meta)
    char     vendor[20];
    char     kind[24];
    char     detail[48];
    char     addr_type[12];
    int8_t   last_rssi;
    int8_t   channel;      // WiFi
    uint8_t  encrypt;      // WiFi authmode-ish
    bool     is_ibeacon;
    char     device_class[32];
};

static RadarSource* radar_sources = nullptr;
static int radar_n = 0;

static void* radar_alloc_mem(size_t n) {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = malloc(n);
    return p;
}

static void radar_clear_all() {
    memset(radar_sources, 0, RADAR_SOURCES * sizeof(RadarSource));
    for (int i = 0; i < RADAR_SOURCES; ++i)
        for (int b = 0; b < RADAR_BINS; ++b) radar_sources[i].rssi[b] = -127;
}

static void radar_alloc() {
    if (radar_sources) return;
    radar_sources = (RadarSource*)radar_alloc_mem(RADAR_SOURCES * sizeof(RadarSource));
    if (!radar_sources) return;
    radar_clear_all();
}

static void radar_reset() {
    radar_alloc();
    radar_n = 0;
    if (radar_sources) radar_clear_all();
}

static int radar_find(const char* id) {
    for (int i = 0; i < radar_n; ++i)
        if (!strcmp(radar_sources[i].id, id)) return i;
    return -1;
}

static int radar_source(const char* id, const char* name) {
    if (!radar_sources) radar_alloc();
    if (!radar_sources) return -1;
    int i = radar_find(id);
    if (i >= 0) return i;
    if (radar_n >= RADAR_SOURCES) return -1;
    i = radar_n++;
    RadarSource& d = radar_sources[i];
    strncpy(d.id, id, sizeof(d.id) - 1);
    copy_ascii(d.name, name, sizeof(d.name));
    d.strongest = -127;
    d.last_rssi = -127;
    d.channel = -1;
    d.seen = millis();
    return i;
}

static void radar_sample(const char* id, const char* name, int rssi, float angle_deg) {
    int i = radar_source(id, name);
    if (i < 0) return;
    float a = fmodf(angle_deg, 360.0f); if (a < 0) a += 360.0f;
    int b = (int)(a * RADAR_BINS / 360.0f) % RADAR_BINS;
    RadarSource& d = radar_sources[i];
    int r = constrain(rssi, -127, 0);
    if (d.hits[b] == 0) d.rssi[b] = (int8_t)r;
    else d.rssi[b] = (int8_t)((d.rssi[b] * 3 + r) / 4);
    if (d.hits[b] < 255) d.hits[b]++;
    if (rssi > d.strongest) d.strongest = rssi;
    d.last_rssi = (int8_t)r;
    d.seen = millis();
}

// Bearing estimate: least-squares fit of  rssi(θ) ≈ a + b·cos θ + c·sin θ  over the
// heading bins that have data. Your body shadows signals from behind, so the
// strength around one turn is roughly a cosine peaking where the source is; the
// fit uses every bin, so a few noisy samples can't drag the answer around.
// Each bin counts (almost) equally however long you stood facing it — the old
// hit-count weighting dragged every dot toward wherever you were pointing.
static bool radar_estimate(const RadarSource& d, float& bearing, float& peak) {
    // normal equations for [a b c]
    static float kCos[RADAR_BINS], kSin[RADAR_BINS];
    static bool trig_ready = false;
    if (!trig_ready) {
        for (int b = 0; b < RADAR_BINS; ++b) {
            float th = (b + 0.5f) * 2.0f * PI / RADAR_BINS;
            kCos[b] = cosf(th); kSin[b] = sinf(th);
        }
        trig_ready = true;
    }
    float s1 = 0, sc = 0, ss = 0, scc = 0, sss = 0, ssc = 0, sy = 0, syc = 0, sys = 0;
    int bins = 0, best = -1;
    for (int b = 0; b < RADAR_BINS; ++b) {
        if (!d.hits[b]) continue;
        float c = kCos[b], s = kSin[b], y = d.rssi[b];
        float w = d.hits[b] >= 2 ? 1.0f : 0.7f;   // a single sample is a bit less trusted
        s1 += w; sc += w * c; ss += w * s;
        scc += w * c * c; sss += w * s * s; ssc += w * s * c;
        sy += w * y; syc += w * y * c; sys += w * y * s;
        ++bins;
        if (best < 0 || d.rssi[b] > d.rssi[best]) best = b;
    }
    if (bins == 0) return false;
    if (bins >= 4) {
        // solve the 3x3 system by Cramer's rule
        float m[3][3] = {{s1, sc, ss}, {sc, scc, ssc}, {ss, ssc, sss}};
        float v[3] = {sy, syc, sys};
        auto det3 = [](float a[3][3]) {
            return a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1])
                 - a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0])
                 + a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0]);
        };
        float D = det3(m);
        if (fabsf(D) > 1e-3f * s1 * s1 * s1) {
            float sol[3];
            for (int k = 0; k < 3; ++k) {
                float t[3][3];
                for (int i = 0; i < 3; ++i)
                    for (int j = 0; j < 3; ++j) t[i][j] = (j == k) ? v[i] : m[i][j];
                sol[k] = det3(t) / D;
            }
            float amp = sqrtf(sol[1] * sol[1] + sol[2] * sol[2]);
            if (amp > 0.3f) {
                float a = atan2f(sol[2], sol[1]) * 180.0f / PI;
                bearing = a < 0 ? a + 360.0f : a;
                peak = constrain(sol[0] + amp, -127.0f, 0.0f);
                return true;
            }
        }
    }
    // too few bins (or flat): fall back to the strongest bin
    bearing = (best + 0.5f) * 360.0f / RADAR_BINS;
    peak = d.rssi[best];
    return true;
}

static float radar_range_from(float peak) {
    float x = constrain(peak + 90.0f, 5.0f, 60.0f) / 60.0f;
    return 0.12f + (1.0f - x) * 0.78f;
}

// ---------------------------------------------------------------------------
//  Gyro heading (dead reckoning, clockwise-positive, 0 = where you started)
// ---------------------------------------------------------------------------
struct RadarHeading {
    float yaw = 0, bx = 0, by = 0, bz = 0;
    uint32_t last_us = 0;
};

static volatile float radar_live_yaw = 0.0f;   // read by the scanner / BLE callback

static void radar_heading_calibrate(RadarHeading& h) {
    float sx = 0, sy = 0, sz = 0;
    int n = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < 800) {
        if (M5.Imu.update()) {
            auto d = M5.Imu.getImuData();
            sx += d.gyro.x; sy += d.gyro.y; sz += d.gyro.z;
            ++n;
        }
        delay(5);
    }
    if (n) { h.bx = sx / n; h.by = sy / n; h.bz = sz / n; }
    h.yaw = 0;
    h.last_us = micros();
}

static float radar_heading_update(RadarHeading& h) {
    if (!M5.Imu.update()) return h.yaw;
    auto d = M5.Imu.getImuData();
    float ax = d.accel.x, ay = d.accel.y, az = d.accel.z;
    float gx = d.gyro.x,  gy = d.gyro.y,  gz = d.gyro.z;
    uint32_t now = micros();
    float dt = (now - h.last_us) * 1e-6f;
    h.last_us = now;
    if (dt <= 0.0f) return h.yaw;
    // A long frame used to be thrown away entirely, silently losing that part of
    // the turn. Integrate it instead (capped so a real stall can't spin the map).
    if (dt > 0.25f) dt = 0.25f;
    float an = sqrtf(ax * ax + ay * ay + az * az);
    if (an < 0.3f) return h.yaw;
    // gravity-projected yaw rate (deg/s about "up") — works held flat or upright
    float rate = ((gx - h.bx) * ax + (gy - h.by) * ay + (gz - h.bz) * az) / an;
    if (fabsf(rate) < 0.6f) rate = 0.0f;
    h.yaw -= YAW_SIGN * rate * dt;
    return h.yaw;
}

// Sample the IMU and publish the heading for the scanner. Called several times
// per frame so turns are integrated at a decent rate even while drawing.
static void heading_tick(RadarHeading& h) {
    radar_live_yaw = radar_heading_update(h);
}

// ---------------------------------------------------------------------------
//  Background scanner
// ---------------------------------------------------------------------------
struct RadarHit {
    char   id[18];
    char   name[28];
    int8_t rssi;
    float  yaw;
    // optional identity (BLE) / meta (WiFi)
    char   vendor[20];
    char   kind[24];
    char   detail[48];
    char   addr_type[12];
    int8_t channel;
    uint8_t encrypt;
    bool   is_ibeacon;
    bool   has_sample;   // carries an RSSI + heading to plot
    bool   has_meta;     // carries identity fields
    char   device_class[32];
};

static QueueHandle_t  radar_q            = nullptr;
static volatile bool  radar_worker_run   = false;
static volatile bool  radar_worker_alive = false;

// Target lock (set by the threat audit's LOCATE): the WiFi radar then scans only
// the target's channel (~6 fixes/s instead of one per sweep) and highlights it.
static char         radar_target_id[18]   = "";
static char         radar_target_name[33] = "";
static volatile int radar_target_ch       = 0;

static BLEScan* ble_scan  = nullptr;
static bool     ble_ready = false;

// Called by the BLE stack the moment an advert arrives, so the sample is stamped
// with the heading at that instant (not the middle of a 1 s scan window).
// Kept deliberately tiny: it runs on the Bluetooth task's stack.
class RadarAdvCallback : public BLEAdvertisedDeviceCallbacks {
public:
    void onResult(BLEAdvertisedDevice d) override {
        if (!radar_q || !radar_worker_run) return;
        RadarHit h;
        memset(&h, 0, sizeof h);
        auto a = d.getAddress().toString();
        strncpy(h.id, a.c_str(), sizeof(h.id) - 1);
        h.rssi = (int8_t)constrain(d.getRSSI(), -127, 0);
        h.yaw = radar_live_yaw;
        h.channel = -1;
        h.has_sample = true;
        xQueueSend(radar_q, &h, 0);
    }
};
static RadarAdvCallback ble_cb;

// WiFi and BLE take turns: only one is scanning at a time.
// The BLE stack is started once and then left up (idle) — tearing it down with
// BLEDevice::deinit() and starting it again is crash-prone on Arduino-ESP32 2.x.
static void wifi_off() {
    if (WiFi.getMode() != WIFI_OFF) {
        WiFi.scanDelete();
        WiFi.mode(WIFI_OFF);
        delay(50);
    }
}

static void ble_stop_scan() {
    if (ble_scan) {
        ble_scan->stop();
        ble_scan->clearResults();
    }
}

static bool radio_setup_wifi() {
    ble_stop_scan();
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    return true;
}

static bool radio_setup_ble() {
    wifi_off();
    if (!ble_ready) {
        BLEDevice::init("");
        ble_scan = BLEDevice::getScan();
        if (!ble_scan) {
            Serial.println("BLE getScan failed");
            return false;
        }
        ble_ready = true;
    }
    // (re)claim the scanner: the threat audit switches it to passive + its own callback
    ble_scan->setAdvertisedDeviceCallbacks(&ble_cb, false);
    ble_scan->setActiveScan(true);
    ble_scan->setInterval(100);
    ble_scan->setWindow(90);
    ble_scan->clearResults();
    return true;
}

static void radio_teardown() {
    ble_stop_scan();
    wifi_off();
}

// BLEScan::start() returns results by value on Arduino-ESP32 2.x and by pointer on 3.x.
template <typename T> static T& scan_results(T& r) { return r; }
template <typename T> static T& scan_results(T* p) { return *p; }

static void radar_worker(void* arg) {
    const bool wifi = (arg != nullptr);
    int ch = 1;
    while (radar_worker_run) {
        if (wifi) {
            float y0 = radar_live_yaw;
            int scan_ch = radar_target_ch > 0 ? radar_target_ch : ch;
            int n = WiFi.scanNetworks(false, true /*show_hidden*/, false /*passive*/,
                                      WIFI_MS_PER_CHANNEL, (uint8_t)scan_ch);
            float ym = (y0 + radar_live_yaw) * 0.5f;
            if (n < 0) n = 0;
            for (int i = 0; i < n && radar_worker_run; ++i) {
                WifiIdentity wid;
                wifi_identify(i, wid);
                RadarHit h;
                memset(&h, 0, sizeof h);
                strncpy(h.id, wid.bssid, sizeof(h.id) - 1);
                strncpy(h.name, wid.ssid, sizeof(h.name) - 1);
                h.rssi = (int8_t)constrain(wid.rssi, -127, 0);
                h.yaw = ym;
                h.channel = wid.channel;
                h.encrypt = wid.encrypt;
                h.has_sample = true;
                h.has_meta = true;
                strncpy(h.vendor, wid.vendor, sizeof(h.vendor) - 1);
                strncpy(h.kind, wid.kind, sizeof(h.kind) - 1);
                strncpy(h.detail, wid.detail, sizeof(h.detail) - 1);
                strncpy(h.device_class, wid.device_class, sizeof(h.device_class) - 1);
                if (radar_q) xQueueSend(radar_q, &h, 0);
            }
            WiFi.scanDelete();
            if (radar_target_ch <= 0) ch = ch % WIFI_MAX_CHANNEL + 1;
            vTaskDelay(pdMS_TO_TICKS(2));
        } else if (ble_scan) {
            // Samples arrive through ble_cb during this call; afterwards we only
            // add identity (name, vendor, class) for what was heard.
            auto res_v = ble_scan->start(1, false);
            auto& res = scan_results(res_v);
            int n = res.getCount();
            for (int i = 0; i < n && radar_worker_run; ++i) {
                BLEAdvertisedDevice d = res.getDevice(i);
                BleIdentity idn;
                ble_identify(d, idn);
                RadarHit h;
                memset(&h, 0, sizeof h);
                strncpy(h.id, idn.addr, sizeof(h.id) - 1);
                strncpy(h.name, idn.name, sizeof(h.name) - 1);
                h.rssi = (int8_t)constrain(idn.rssi, -127, 0);
                h.yaw = radar_live_yaw;
                h.has_meta = true;
                h.is_ibeacon = idn.is_ibeacon;
                h.channel = -1;
                strncpy(h.vendor, idn.vendor, sizeof(h.vendor) - 1);
                strncpy(h.kind, idn.kind, sizeof(h.kind) - 1);
                strncpy(h.detail, idn.detail, sizeof(h.detail) - 1);
                strncpy(h.addr_type, idn.addr_type, sizeof(h.addr_type) - 1);
                strncpy(h.device_class, idn.device_class, sizeof(h.device_class) - 1);
                if (radar_q) xQueueSend(radar_q, &h, 0);
            }
            ble_scan->clearResults();
            vTaskDelay(pdMS_TO_TICKS(10));
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    radar_worker_alive = false;
    vTaskDelete(nullptr);
}

static void radar_worker_start(bool wifi) {
    if (!radar_q) radar_q = xQueueCreate(128, sizeof(RadarHit));
    xQueueReset(radar_q);
    radar_worker_run = true;
    radar_worker_alive = true;
    xTaskCreatePinnedToCore(radar_worker, "radar", 10240,
                            wifi ? (void*)1 : nullptr, 2, nullptr, 0);
}

// Waits until the scanner task has really finished before the radio is touched.
// (The old 4 s timeout was shorter than one WiFi sweep, so the radio could be
// switched off under a scan that was still running.)
static void radar_worker_stop() {
    radar_worker_run = false;
    uint32_t t0 = millis();
    while (radar_worker_alive && millis() - t0 < 15000) delay(20);
    if (radar_worker_alive) Serial.println("WARN: radar worker still running after 15 s");
    if (radar_q) xQueueReset(radar_q);
}

static void radar_drain() {
    RadarHit h;
    int budget = 96;   // keep the frame rate up even if the queue is full
    while (budget-- > 0 && radar_q && xQueueReceive(radar_q, &h, 0) == pdTRUE) {
        if (h.has_sample) radar_sample(h.id, h.name, h.rssi, h.yaw);
        if (!h.has_meta) continue;
        int idx = radar_source(h.id, h.name);   // list it even if its sample was dropped
        if (idx < 0) continue;
        RadarSource& d = radar_sources[idx];
        if (h.name[0] && strcmp(h.name, "(no name)")) copy_ascii(d.name, h.name, sizeof(d.name));
        copy_ascii(d.vendor, h.vendor, sizeof(d.vendor));
        copy_ascii(d.kind, h.kind, sizeof(d.kind));
        copy_ascii(d.detail, h.detail, sizeof(d.detail));
        copy_ascii(d.addr_type, h.addr_type, sizeof(d.addr_type));
        if (h.device_class[0]) copy_ascii(d.device_class, h.device_class, sizeof(d.device_class));
        d.is_ibeacon = h.is_ibeacon;
        d.last_rssi = h.rssi;
        if (h.rssi > d.strongest) d.strongest = h.rssi;
        if (h.channel >= 0) d.channel = h.channel;
        d.encrypt = h.encrypt;
        d.seen = millis();
    }
}

// ---------------------------------------------------------------------------
//  Input
// ---------------------------------------------------------------------------
// A finished tap on the display itself. The Core2's A/B/C "buttons" are part of
// the same touch panel just below the screen; those touches are ignored here so
// pressing B can never also count as a tap on the bottom of the screen.
static bool screen_tap(int& x, int& y) {
    auto t = M5.Touch.getDetail();
    if (!t.wasClicked()) return false;
    if (t.x < 0 || t.x >= SCREEN_W || t.y < 0 || t.y >= SCREEN_H) return false;
    x = t.x; y = t.y;
    return true;
}

static bool btn_exit() {
    return M5.BtnC.wasClicked() || M5.BtnC.wasHold() || M5.BtnA.wasHold();
}

// ---------------------------------------------------------------------------
//  Drawing
// ---------------------------------------------------------------------------
enum RadarPhase { RADAR_CAL, RADAR_MEASURE, RADAR_LIVE };

static M5Canvas* canvas = nullptr;

struct Blip { int16_t x, y; int8_t src; };
static Blip blips[RADAR_SOURCES];
static int  blip_n = 0;

static void draw_mantis(M5Canvas* c, int cx, int cy) {
    const int ox = cx - MANTIS_W / 2;
    const int oy = cy - MANTIS_H / 2;
    for (int y = 0; y < MANTIS_H; ++y) {
        for (int x = 0; x < MANTIS_W; ++x) {
            int idx = y * MANTIS_W + x;
            if (!mantis_alpha[idx]) continue;
            c->drawPixel(ox + x, oy + y, mantis_rgb565[idx]);
        }
    }
}

// Draw text, trimmed so it never runs past maxw pixels.
static void draw_fit(const char* s, int x, int y, int maxw) {
    char buf[64];
    strncpy(buf, s ? s : "", sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    int n = (int)strlen(buf);
    while (n > 0 && canvas->textWidth(buf) > maxw) buf[--n] = 0;
    canvas->drawString(buf, x, y);
}

static void radar_draw(float green, float red, bool wifi, RadarPhase ph, float heading) {
    if (!canvas) return;
    canvas->fillSprite(COL_BG);

    auto at = [&](float deg, float r, int& x, int& y) {
        float a = deg * PI / 180.0f;
        x = CX + (int)lroundf(r * sinf(a));
        y = CY - (int)lroundf(r * cosf(a));
    };

    for (int r = 20; r <= R; r += 20)
        canvas->drawCircle(CX, CY, r, COL_GRID);
    canvas->drawCircle(CX, CY, R, COL_RING);

    float sweep_now = fmodf(millis() * 0.18f, 360.0f);

    if (ph == RADAR_MEASURE) {
        float cov = fminf(fabsf(green), 360.0f);
        if (cov > 1.0f) {
            // fillArc: 0° = 3 o'clock, clockwise; 270° = 12 o'clock
            if (green >= 0) canvas->fillArc(CX, CY, R + 6, R + 3, 270.0f, 270.0f + cov, COL_TEAL);
            else            canvas->fillArc(CX, CY, R + 6, R + 3, 270.0f - cov, 270.0f, COL_TEAL);
        }
        int x, y;
        at(fmodf(red, 360.0f), R, x, y);
        canvas->drawWideLine(CX, CY, x, y, 2.0f, COL_RED);
        at(fmodf(green + 3600.0f, 360.0f), R - 6, x, y);
        canvas->drawWideLine(CX, CY, x, y, 2.0f, COL_LIME);
    } else if (ph == RADAR_LIVE) {
        for (int t = 60; t >= 0; t -= 6) {
            int x, y;
            at(sweep_now - t, R, x, y);
            uint8_t v = (uint8_t)((63 - t) >> 1);
            uint16_t col = ((v >> 1) << 11) | ((v) << 5) | (v >> 2);   // teal-ish fade
            canvas->drawLine(CX, CY, x, y, col);
        }
        // "you are facing" marker
        canvas->fillTriangle(CX - 6, CY - R - 2, CX + 6, CY - R - 2,
                             CX, CY - R + 8, COL_TEAL);
    }

    blip_n = 0;
    bool  tgt_found = false;
    float tgt_disp  = 0;
    for (int i = 0; i < radar_n; ++i) {
        RadarSource& d = radar_sources[i];
        float bearing, peak;
        if (!radar_estimate(d, bearing, peak)) continue;
        float disp = (ph == RADAR_LIVE) ? bearing - heading : bearing;
        disp = fmodf(fmodf(disp, 360.0f) + 360.0f, 360.0f);
        int x, y;
        at(disp, R * radar_range_from(peak), x, y);
        bool lit = false;
        if (ph == RADAR_LIVE) {
            float da = fabsf(disp - sweep_now);
            if (da > 180) da = 360 - da;
            lit = da < 18.0f;
        }
        uint16_t col = lit ? COL_LIME
                           : (d.seen && millis() - d.seen < 3000 ? COL_TEAL : COL_DIM);
        bool is_target = radar_target_id[0] && !strcmp(d.id, radar_target_id);
        if (is_target) {
            // target lock: bearing line + pulsing double ring
            canvas->drawLine(CX, CY, x, y, COL_RED);
            int pr = 9 + (int)((millis() / 60) % 10);
            canvas->drawCircle(x, y, pr, COL_RED);
            canvas->drawCircle(x, y, pr + 1, COL_RED);
            col = COL_RED;
            tgt_found = true;
            tgt_disp = disp;
        }
        canvas->fillCircle(x, y, (lit || is_target) ? 6 : 4, col);
        blips[blip_n++] = { (int16_t)x, (int16_t)y, (int8_t)i };
    }

    draw_mantis(canvas, CX, CY);

    canvas->setTextSize(1);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    if (radar_target_id[0]) {
        char tb[48];
        snprintf(tb, sizeof tb, "TRACKING %s", radar_target_name[0] ? radar_target_name : radar_target_id);
        canvas->setTextColor(COL_RED);
        draw_fit(tb, 4, 2, 270);
    } else {
        canvas->setTextColor(COL_TEAL);
        canvas->drawString(wifi ? "WIFI RADAR" : "BLE RADAR", 4, 2);
    }

    canvas->setTextDatum(top_right);
    canvas->setTextColor(COL_LIME);
    char nbuf[12];
    snprintf(nbuf, sizeof nbuf, "%d", radar_n);
    canvas->drawString(nbuf, 316, 2);

    canvas->setFont(&fonts::Font0);
    canvas->setTextDatum(bottom_center);
    canvas->setTextColor(COL_HINT);
    const char* hint = ph == RADAR_CAL
        ? "hold still..."
        : ph == RADAR_MEASURE
            ? (green < -25.0f ? "other way!" : "turn slowly: keep green on red")
            : "A rescan   B list   C exit   tap a dot = info";
    char tgt_hint[40];
    if (ph == RADAR_LIVE && radar_target_id[0]) {
        // steer the user onto the target
        if (!tgt_found) {
            snprintf(tgt_hint, sizeof tgt_hint, "ACQUIRING TARGET...");
        } else {
            float rel = tgt_disp > 180.0f ? tgt_disp - 360.0f : tgt_disp;
            if (fabsf(rel) < 12.0f) snprintf(tgt_hint, sizeof tgt_hint, ">>  TARGET DEAD AHEAD  <<");
            else snprintf(tgt_hint, sizeof tgt_hint, "TARGET %s %d DEG", rel > 0 ? "RIGHT" : "LEFT",
                          (int)lroundf(fabsf(rel)));
        }
        canvas->setTextColor(COL_RED);
        hint = tgt_hint;
    }
    canvas->drawString(hint, 160, 238);

    canvas->pushSprite(0, 0);
}

// Nearest radar dot to a tap (within ~20 px), or -1.
static int blip_at(int x, int y) {
    int best = -1, bd = 20 * 20;
    for (int i = 0; i < blip_n; ++i) {
        int dx = blips[i].x - x, dy = blips[i].y - y;
        int dd = dx * dx + dy * dy;
        if (dd <= bd) { bd = dd; best = blips[i].src; }
    }
    return best;
}

// ---------------------------------------------------------------------------
//  Device detail + list screens (WiFi + BLE)
// ---------------------------------------------------------------------------
static void draw_device_detail(bool wifi, int src) {
    if (!canvas || src < 0 || src >= radar_n) return;
    RadarSource& d = radar_sources[src];
    canvas->fillSprite(COL_BG);
    canvas->setTextSize(1);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    canvas->setTextColor(COL_TEAL);
    canvas->drawString(wifi ? "WiFi AP detail" : "BLE device detail", 6, 4);

    int y = 28;
    auto line = [&](const char* label, const char* val) {
        canvas->setTextColor(COL_HINT);
        canvas->drawString(label, 8, y);
        canvas->setTextColor(COL_TEXT);
        draw_fit(val && val[0] ? val : "-", 84, y, SCREEN_W - 84 - 6);
        y += 18;
    };
    char buf[48];
    if (d.device_class[0]) line("Type", d.device_class);
    line("Name", d.name);
    line(wifi ? "BSSID" : "Addr", d.id);
    snprintf(buf, sizeof buf, "%d dBm  (last %d)", d.strongest, (int)d.last_rssi);
    line("RSSI", buf);
    float bearing, peak;
    if (radar_estimate(d, bearing, peak)) snprintf(buf, sizeof buf, "%.0f deg from start", bearing);
    else snprintf(buf, sizeof buf, "not enough samples");
    line("Bearing", buf);
    line("Vendor", d.vendor);
    if (wifi) {
        line("Radio", d.kind);
        line("Meta", d.detail);
    } else {
        snprintf(buf, sizeof buf, "%s%s", d.kind, d.is_ibeacon ? "  (iBeacon)" : "");
        line("Kind", buf);
        line("AddrType", d.addr_type);
        line("Detail", d.detail);
    }
    snprintf(buf, sizeof buf, "%lus ago", (unsigned long)((millis() - d.seen) / 1000));
    line("Seen", buf);

    canvas->setFont(&fonts::Font0);
    canvas->setTextDatum(bottom_center);
    canvas->setTextColor(COL_HINT);
    canvas->drawString("tap or any button = back", 160, 238);
    canvas->pushSprite(0, 0);
}

static void device_detail_screen(bool wifi, int src, RadarHeading& hd) {
    Serial.printf("detail: %d\n", src);
    draw_device_detail(wifi, src);
    uint32_t last = millis();
    for (;;) {
        M5.update();
        heading_tick(hd);
        radar_drain();
        if (M5.BtnA.wasClicked() || M5.BtnB.wasClicked() ||
            M5.BtnC.wasClicked() || M5.BtnC.wasHold()) break;
        int tx, ty;
        if (screen_tap(tx, ty)) break;
        if (millis() - last > 1000) { last = millis(); draw_device_detail(wifi, src); }
        delay(15);
    }
}

static int list_order[RADAR_SOURCES];
static int list_count = 0;

static void list_build_sorted() {
    list_count = radar_n;
    for (int i = 0; i < list_count; ++i) list_order[i] = i;
    // strongest RSSI first (insertion sort; n ≤ 32)
    for (int a = 1; a < list_count; ++a) {
        int v = list_order[a], b = a - 1;
        while (b >= 0 && radar_sources[list_order[b]].strongest < radar_sources[v].strongest) {
            list_order[b + 1] = list_order[b];
            --b;
        }
        list_order[b + 1] = v;
    }
}

static int list_pos_of(int src) {
    for (int i = 0; i < list_count; ++i) if (list_order[i] == src) return i;
    return -1;
}

static constexpr int LIST_TOP = 30, LIST_ROW_H = 36, LIST_VISIBLE = 5;
static constexpr int BACK_X = 4, BACK_Y = 3, BACK_W = 60, BACK_H = 22;

static void draw_device_list(bool wifi, int sel_src, int scroll) {
    if (!canvas) return;
    canvas->fillSprite(COL_BG);
    canvas->setTextSize(1);

    // header: back chip · title · count
    canvas->fillRoundRect(BACK_X, BACK_Y, BACK_W, BACK_H, 5, COL_PANEL);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(middle_center);
    canvas->setTextColor(COL_LIME);
    canvas->drawString("< back", BACK_X + BACK_W / 2, BACK_Y + BACK_H / 2);
    canvas->setTextColor(COL_TEAL);
    canvas->drawString(wifi ? "WiFi devices" : "BLE devices", 160, BACK_Y + BACK_H / 2);
    canvas->setTextDatum(middle_right);
    canvas->setTextColor(COL_LIME);
    char nb[12];
    snprintf(nb, sizeof nb, "%d", list_count);
    canvas->drawString(nb, 314, BACK_Y + BACK_H / 2);

    if (list_count == 0) {
        canvas->setTextDatum(middle_center);
        canvas->setTextColor(COL_HINT);
        canvas->drawString("no devices yet - keep scanning", 160, 120);
    }

    for (int row = 0; row < LIST_VISIBLE; ++row) {
        int li = scroll + row;
        if (li >= list_count) break;
        int src = list_order[li];
        RadarSource& d = radar_sources[src];
        int y = LIST_TOP + row * LIST_ROW_H;
        bool on = (src == sel_src);
        canvas->fillRoundRect(4, y, 312, LIST_ROW_H - 3, 6, on ? COL_TEAL : COL_PANEL);

        // line 1: name (Font2) + RSSI
        canvas->setFont(&fonts::Font2);
        canvas->setTextDatum(top_right);
        canvas->setTextColor(on ? COL_BG : COL_LIME);
        char rs[12];
        if (d.strongest > -127) snprintf(rs, sizeof rs, "%d dBm", d.strongest);
        else snprintf(rs, sizeof rs, "--");
        canvas->drawString(rs, 310, y + 2);
        int rs_w = canvas->textWidth(rs);
        canvas->setTextDatum(top_left);
        canvas->setTextColor(on ? COL_BG : COL_TEXT);
        draw_fit(d.name[0] ? d.name : d.id, 10, y + 2, 310 - rs_w - 10 - 8);

        // line 2: what it is (Font0)
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(on ? COL_BG : COL_HINT);
        char line2[96];
        if (wifi) {
            if (d.device_class[0])
                snprintf(line2, sizeof line2, "%s | %s", d.device_class, d.kind);
            else
                snprintf(line2, sizeof line2, "%s | %s", d.id, d.detail);
        } else {
            if (d.device_class[0])
                snprintf(line2, sizeof line2, "%s | %s", d.device_class, d.vendor[0] ? d.vendor : "-");
            else
                snprintf(line2, sizeof line2, "%s | %s | %s",
                         d.vendor[0] ? d.vendor : "-", d.kind, d.addr_type);
        }
        draw_fit(line2, 10, y + 21, 300);
    }

    // scroll position
    if (list_count > LIST_VISIBLE) {
        int track = LIST_VISIBLE * LIST_ROW_H;
        int th = std::max(12, track * LIST_VISIBLE / list_count);
        int ty = LIST_TOP + (track - th) * scroll / (list_count - LIST_VISIBLE);
        canvas->fillRect(317, ty, 3, th, COL_DIM);
    }

    canvas->setFont(&fonts::Font0);
    canvas->setTextDatum(bottom_center);
    canvas->setTextColor(COL_HINT);
    canvas->drawString("tap row, tap again = info   A up  B down  C back", 160, 238);
    canvas->pushSprite(0, 0);
}

// Returns when the user leaves the list. The scanner keeps running and the
// heading keeps being tracked, so the radar is still lined up afterwards.
static void device_list_screen(bool wifi, RadarHeading& hd) {
    Serial.println("list: open");
    log_heap("list");
    radar_drain();
    list_build_sorted();
    int sel_src = list_count ? list_order[0] : -1;
    int scroll = 0;
    bool dirty = true;
    uint32_t last_sort = millis();

    auto keep_visible = [&]() {
        int maxs = std::max(0, list_count - LIST_VISIBLE);
        int p = list_pos_of(sel_src);
        if (p >= 0) {
            if (p < scroll) scroll = p;
            if (p >= scroll + LIST_VISIBLE) scroll = p - LIST_VISIBLE + 1;
        }
        scroll = constrain(scroll, 0, maxs);
    };
    auto move_sel = [&](int delta) {
        if (!list_count) return;
        int p = list_pos_of(sel_src);
        if (p < 0) p = 0;
        else p = (p + delta % list_count + list_count) % list_count;
        sel_src = list_order[p];
        dirty = true;
    };

    for (;;) {
        M5.update();
        heading_tick(hd);
        radar_drain();

        if (M5.BtnC.wasClicked() || M5.BtnC.wasHold()) break;
        if (M5.BtnB.wasClicked()) move_sel(+1);
        if (M5.BtnA.wasClicked()) move_sel(-1);
        if (M5.BtnA.wasHold() && sel_src >= 0) {
            device_detail_screen(wifi, sel_src, hd);
            dirty = true;
        }

        auto t = M5.Touch.getDetail();
        if ((t.wasFlicked() || t.wasDragged()) && t.base_y < SCREEN_H && list_count) {
            int dy = t.distanceY();
            if (dy < -20) move_sel(+LIST_VISIBLE);       // swipe up → further down the list
            else if (dy > 20) move_sel(-LIST_VISIBLE);
        }
        int tx, ty;
        if (screen_tap(tx, ty)) {
            if (tx < BACK_X + BACK_W + 6 && ty < BACK_Y + BACK_H + 6) break;
            if (ty >= LIST_TOP && ty < LIST_TOP + LIST_VISIBLE * LIST_ROW_H) {
                int p = scroll + (ty - LIST_TOP) / LIST_ROW_H;
                if (p < list_count) {
                    int s = list_order[p];
                    if (s == sel_src) device_detail_screen(wifi, s, hd);
                    else sel_src = s;
                    dirty = true;
                }
            }
        }

        if (millis() - last_sort > 1500) {
            last_sort = millis();
            list_build_sorted();
            if (sel_src < 0 && list_count) sel_src = list_order[0];
            dirty = true;
        }
        if (dirty) {
            keep_visible();
            draw_device_list(wifi, sel_src, scroll);
            dirty = false;
        }
        delay(15);
    }
    Serial.println("list: close");
}

// ---------------------------------------------------------------------------
//  Radar run
// ---------------------------------------------------------------------------
static void show_message(const char* msg, uint16_t col) {
    canvas->fillSprite(COL_BG);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(middle_center);
    canvas->setTextColor(col);
    canvas->drawString(msg, 160, 120);
    canvas->pushSprite(0, 0);
}

static void radar_run(bool wifi) {
    for (;;) {
        Serial.printf("radar: start %s\n", wifi ? "wifi" : "ble");
        radar_reset();
        blip_n = 0;

        bool ok = wifi ? radio_setup_wifi() : radio_setup_ble();
        log_heap("radio up");
        if (!ok) {
            show_message("radio failed to start", COL_RED);
            delay(1500);
            radio_teardown();
            return;
        }

        radar_draw(0, 0, wifi, RADAR_CAL, 0);
        RadarHeading hd;
        radar_heading_calibrate(hd);
        radar_live_yaw = 0;
        radar_worker_start(wifi);

        // --- sweep: one full turn while the scanner fills the bins ---
        const float TARGET_DPS = 18.0f;
        uint32_t t0 = millis();
        bool quit = false;
        for (;;) {
            uint32_t f0 = millis();
            M5.update();
            if (btn_exit()) { quit = true; break; }
            heading_tick(hd);
            radar_drain();
            float red = fminf(360.0f, (millis() - t0) * 0.001f * TARGET_DPS);
            radar_draw(hd.yaw, red, wifi, RADAR_MEASURE, 0);
            heading_tick(hd);
            if (fabsf(hd.yaw) >= 360.0f) break;
            if (millis() - t0 > 60000) break;
            uint32_t el = millis() - f0;
            if (el < 30) delay(30 - el);
        }

        // --- live: map stays fixed to the world, rotates as you turn ---
        // The heading is NOT wrapped here: wrapping mid-scan made the scanner
        // average e.g. 359° and 1° into 180°.
        bool rescan = false;
        while (!quit) {
            uint32_t f0 = millis();
            M5.update();
            heading_tick(hd);
            if (btn_exit()) { quit = true; break; }
            if (M5.BtnA.wasClicked()) { rescan = true; break; }
            if (M5.BtnB.wasClicked()) {
                device_list_screen(wifi, hd);
                continue;
            }
            int tx, ty;
            if (screen_tap(tx, ty)) {
                int s = blip_at(tx, ty);
                if (s >= 0) { device_detail_screen(wifi, s, hd); continue; }
            }
            radar_drain();
            radar_draw(0, 0, wifi, RADAR_LIVE, hd.yaw);
            heading_tick(hd);
            uint32_t el = millis() - f0;
            if (el < 33) delay(33 - el);
        }

        radar_worker_stop();
        radio_teardown();
        log_heap("radio down");
        if (quit || !rescan) return;
        // rescan: loop again; setup runs at the top of the next iteration
    }
}

// ---------------------------------------------------------------------------
//  WiFi threat audit (SITREP) — passive monitor-mode threat scanner
// ---------------------------------------------------------------------------
#include "threat_audit.h"

// ---------------------------------------------------------------------------
//  Splash + menu
// ---------------------------------------------------------------------------
static void draw_splash() {
    M5.Display.fillScreen(COL_BG);
    M5.Display.setTextDatum(middle_center);
    M5.Display.setTextColor(COL_TEAL);
    M5.Display.setFont(&fonts::Font4);
    M5.Display.drawString("DeviceRadar", 160, 90);
    M5.Display.setFont(&fonts::Font2);
    M5.Display.setTextColor(COL_LIME);
    M5.Display.drawString("Mantis Edition", 160, 125);
    M5.Display.setTextColor(COL_HINT);
    M5.Display.setFont(&fonts::Font0);
    M5.Display.drawString("WiFi + BLE rotational radar", 160, 160);
    M5.Display.drawString("Core2 + M5Unified", 160, 180);
    for (int y = 0; y < MANTIS_H; ++y)
        for (int x = 0; x < MANTIS_W; ++x) {
            int idx = y * MANTIS_W + x;
            if (!mantis_alpha[idx]) continue;
            M5.Display.drawPixel(160 - MANTIS_W/2 + x, 50 - MANTIS_H/2 + y, mantis_rgb565[idx]);
        }
    delay(1800);
}

static constexpr int MENU_N = 3;
static constexpr int MENU_X = 40, MENU_W = 240, MENU_H = 40;
static const int     MENU_Y[MENU_N] = {92, 140, 188};   // item centres
static const char*   MENU_LABEL[MENU_N] = {"WiFi Radar", "BLE Radar", "Threat Audit"};

// Which menu item (if any) is under a touch point. Hit boxes are a little
// taller than the drawn buttons so near-misses still count.
static int menu_hit(int x, int y) {
    if (x < MENU_X - 10 || x >= MENU_X + MENU_W + 10) return -1;
    for (int i = 0; i < MENU_N; ++i)
        if (y >= MENU_Y[i] - 24 && y < MENU_Y[i] + 24) return i;
    return -1;
}

static void draw_menu(int sel) {
    canvas->fillSprite(COL_BG);
    canvas->setTextSize(1);
    canvas->setTextDatum(top_center);
    canvas->setTextColor(COL_TEAL);
    canvas->setFont(&fonts::Font4);
    canvas->drawString("DeviceRadar", 160, 12);

    canvas->setFont(&fonts::Font0);
    canvas->setTextColor(COL_MAGENTA);
    canvas->drawString("MANTIS", 160, 48);

    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(middle_center);
    for (int i = 0; i < MENU_N; ++i) {
        bool on = (sel == i);
        int y = MENU_Y[i];
        canvas->fillRoundRect(MENU_X, y - MENU_H / 2, MENU_W, MENU_H, 8, on ? COL_TEAL : COL_PANEL);
        if (on) canvas->drawRoundRect(MENU_X, y - MENU_H / 2, MENU_W, MENU_H, 8, COL_LIME);
        // the audit gets the spy-kit red accent
        canvas->setTextColor(on ? COL_BG : (i == 2 ? COL_RED : COL_TEXT));
        canvas->drawString(MENU_LABEL[i], 160, y);
    }

    canvas->setTextDatum(bottom_center);
    canvas->setTextColor(COL_HINT);
    canvas->setFont(&fonts::Font0);
    canvas->drawString("tap or A = start   B = next   hold C = power off", 160, 236);
    canvas->pushSprite(0, 0);
}

static void menu_loop() {
    int sel = 0;
    draw_menu(sel);
    for (;;) {
        M5.update();
        int launch = -1;

        if (M5.BtnB.wasClicked()) {
            sel = (sel + 1) % MENU_N;
            draw_menu(sel);
        }
        if (M5.BtnA.wasClicked()) launch = sel;

        // Highlight follows your finger; releasing on an item starts that item.
        auto t = M5.Touch.getDetail();
        if (t.wasPressed() && t.y < SCREEN_H) {
            int h = menu_hit(t.x, t.y);
            if (h >= 0 && h != sel) { sel = h; draw_menu(sel); }
        }
        int tx, ty;
        if (screen_tap(tx, ty)) {
            int h = menu_hit(tx, ty);
            if (h >= 0) launch = h;
        }

        if (launch >= 0) {
            sel = launch;
            draw_menu(sel);
            delay(120);
            if (sel == 2) threat_audit_run();
            else radar_run(sel == 0);
            draw_menu(sel);
        }
        if (M5.BtnC.wasHold()) {
            M5.Power.powerOff();
        }
        delay(15);
    }
}

// ---------------------------------------------------------------------------
void setup() {
    auto cfg = M5.config();
    cfg.clear_display = true;
    M5.begin(cfg);

    M5.Display.setBrightness(180);
    M5.Display.setRotation(1);
    M5.Display.fillScreen(COL_BG);

    Serial.begin(115200);
    Serial.println("DeviceRadar (Mantis) ready");

    // Full-screen frame buffer goes in PSRAM: 150 KB of internal RAM is too much
    // to give up next to the WiFi and BLE stacks.
    canvas = new M5Canvas(&M5.Display);
    canvas->setColorDepth(16);
    canvas->setPsram(true);
    if (!canvas->createSprite(SCREEN_W, SCREEN_H)) {
        canvas->setPsram(false);
        canvas->createSprite(SCREEN_W, SCREEN_H);
    }

    CX = 160; CY = 120; R = 95;

    // Optional SD: place ble_ids.txt at card root for extended company/service names
    // Core2 SD pins: SCK=18 MISO=38 MOSI=23 CS=4
    SPI.begin(18, 38, 23, 4);
    if (SD.begin(4, SPI, 25000000)) {
        Serial.println("SD mounted — loading /ble_ids.txt if present");
    } else {
        Serial.println("SD not present (embedded ID tables still active)");
    }
    // Load the table now, on this core. The SD card shares its SPI bus with the
    // display, so reading it later from the scanner task (other core) while the
    // screen is drawing can corrupt both.
    ble_id_load_sd();

    // Core2 ships with MPU6886; M5Unified exposes it via M5.Imu
    bool imu_ok = false;
    for (int i = 0; i < 20; ++i) {
        if (M5.Imu.update()) { imu_ok = true; break; }
        delay(20);
    }
    if (!imu_ok) {
        M5.Display.setTextColor(COL_RED);
        M5.Display.setTextDatum(middle_center);
        M5.Display.drawString("No IMU detected", 160, 120);
        while (1) delay(1000);
    }

    log_heap("boot");
    radar_alloc();
    draw_splash();
    menu_loop();
}

void loop() {
    delay(1000);
}
