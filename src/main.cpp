/**
 * DeviceRadar — M5Stack Core2
 *
 * Standalone WiFi + BLE rotational radar.
 * Ported from the Fox Voice Companion radar tools.
 * Mantis theme · M5Unified · single merged binary.
 *
 * Controls:
 *   BtnA  – select / confirm / rescan
 *   BtnB  – next menu item
 *   BtnC  – exit radar / long-press power off
 *   Touch – menu select & exit
 */

#include <M5Unified.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <esp_heap_caps.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <math.h>
#include <string.h>
#include "mantis_sprite.h"

// ---------------------------------------------------------------------------
//  Mantis theme colours (RGB565)
//  #007373 teal · #5d005d purple · lime · dark grey
// ---------------------------------------------------------------------------
static constexpr uint16_t COL_BG       = 0x18C3;   // #1a1a1a dark grey
static constexpr uint16_t COL_PANEL    = 0x2965;   // #2d2d2d mid grey
static constexpr uint16_t COL_TEAL     = 0x038E;   // #007373
static constexpr uint16_t COL_PURPLE   = 0x580B;   // #5d005d
static constexpr uint16_t COL_LIME     = 0xB7E0;   // lime green
static constexpr uint16_t COL_ACCENT   = COL_TEAL;
static constexpr uint16_t COL_PRIMARY  = COL_LIME;
static constexpr uint16_t COL_GRID     = 0x31A6;
static constexpr uint16_t COL_RING     = 0x4208;
static constexpr uint16_t COL_GREEN    = COL_LIME;
static constexpr uint16_t COL_RED      = 0xF800;
static constexpr uint16_t COL_DIM      = 0x8410;
static constexpr uint16_t COL_HINT     = 0x9CF3;
static constexpr uint16_t COL_TEXT     = 0xEF5D;

static constexpr int RADAR_SOURCES = 32;
static constexpr int RADAR_BINS    = 72;

static int CX = 160, CY = 120, R = 95;

// ---------------------------------------------------------------------------
//  Radar data
// ---------------------------------------------------------------------------
struct RadarSource {
    char     id[18];
    char     name[24];
    int8_t   rssi[RADAR_BINS];
    uint8_t  hits[RADAR_BINS];
    int      strongest;
    uint32_t seen;
};

static RadarSource* radar_sources = nullptr;
static int radar_n = 0;

static void* radar_alloc_mem(size_t n) {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = malloc(n);
    return p;
}

static void radar_alloc() {
    if (radar_sources) return;
    radar_sources = (RadarSource*)radar_alloc_mem(RADAR_SOURCES * sizeof(RadarSource));
    if (!radar_sources) return;
    memset(radar_sources, 0, RADAR_SOURCES * sizeof(RadarSource));
    for (int i = 0; i < RADAR_SOURCES; ++i)
        for (int b = 0; b < RADAR_BINS; ++b) radar_sources[i].rssi[b] = -127;
}

static void radar_reset() {
    radar_alloc();
    radar_n = 0;
    if (!radar_sources) return;
    memset(radar_sources, 0, RADAR_SOURCES * sizeof(RadarSource));
    for (int i = 0; i < RADAR_SOURCES; ++i)
        for (int b = 0; b < RADAR_BINS; ++b) radar_sources[i].rssi[b] = -127;
}

static int radar_find(const char* id) {
    for (int i = 0; i < radar_n; ++i)
        if (!strcmp(radar_sources[i].id, id)) return i;
    return -1;
}

static int radar_source(const char* id, const String& name) {
    int i = radar_find(id);
    if (i >= 0) return i;
    if (radar_n >= RADAR_SOURCES) return -1;
    i = radar_n++;
    strncpy(radar_sources[i].id, id, sizeof(radar_sources[i].id) - 1);
    strncpy(radar_sources[i].name, name.c_str(), sizeof(radar_sources[i].name) - 1);
    radar_sources[i].strongest = -127;
    return i;
}

static void radar_sample(const char* id, const String& name, int rssi, float angle_deg) {
    if (!radar_sources) radar_alloc();
    if (!radar_sources) return;
    int i = radar_source(id, name);
    if (i < 0) return;
    float a = fmodf(angle_deg, 360.0f); if (a < 0) a += 360.0f;
    int b = (int)(a * RADAR_BINS / 360.0f) % RADAR_BINS;
    RadarSource& d = radar_sources[i];
    if (d.hits[b] == 0) d.rssi[b] = (int8_t)constrain(rssi, -127, 0);
    else d.rssi[b] = (int8_t)((d.rssi[b] * 3 + constrain(rssi, -127, 0)) / 4);
    if (d.hits[b] < 255) d.hits[b]++;
    if (rssi > d.strongest) d.strongest = rssi;
    d.seen = millis();
}

static float radar_peak_angle(const RadarSource& d) {
    int peak = d.strongest;
    float sx = 0, sy = 0, wsum = 0;
    for (int b = 0; b < RADAR_BINS; ++b) {
        if (!d.hits[b]) continue;
        int db = peak - d.rssi[b];
        if (db > 12) continue;
        float w = (float)(13 - db) * d.hits[b];
        float a = (b + 0.5f) * 2.0f * PI / RADAR_BINS;
        sx += cosf(a) * w; sy += sinf(a) * w; wsum += w;
    }
    if (wsum < 1) return 0;
    float a = atan2f(sy, sx) * 180.0f / PI;
    if (a < 0) a += 360.0f;
    return a;
}

static float radar_range(const RadarSource& d) {
    float x = constrain((float)(d.strongest + 90), 5.0f, 60.0f) / 60.0f;
    return 0.12f + (1.0f - x) * 0.78f;
}

// ---------------------------------------------------------------------------
//  Gyro heading
// ---------------------------------------------------------------------------
struct RadarHeading {
    float yaw = 0, bx = 0, by = 0, bz = 0;
    uint32_t last_us = 0;
};

static void radar_heading_calibrate(RadarHeading& h) {
    float sx = 0, sy = 0, sz = 0;
    int n = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < 600) {
        // Preferred M5Unified path: update() then getImuData()
        if (M5.Imu.update()) {
            auto d = M5.Imu.getImuData();
            sx += d.gyro.x; sy += d.gyro.y; sz += d.gyro.z;
            ++n;
        }
        delay(10);
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
    if (dt <= 0.0f || dt > 0.1f) return h.yaw;
    float an = sqrtf(ax * ax + ay * ay + az * az);
    if (an < 0.3f) return h.yaw;
    // gravity-projected yaw rate (deg/s about "up")
    float rate = ((gx - h.bx) * ax + (gy - h.by) * ay + (gz - h.bz) * az) / an;
    if (fabsf(rate) < 0.8f) rate = 0.0f;
    h.yaw -= rate * dt;
    return h.yaw;
}

// ---------------------------------------------------------------------------
//  Background scanner
// ---------------------------------------------------------------------------
struct RadarHit {
    char   id[18];
    char   name[24];
    int8_t rssi;
    float  yaw;
};

static QueueHandle_t  radar_q            = nullptr;
static volatile float radar_live_yaw     = 0.0f;
static volatile bool  radar_worker_run   = false;
static volatile bool  radar_worker_alive = false;

static BLEScan* ble_scan = nullptr;
static bool ble_initialized = false;

// Each radar mode fully owns radio setup and teardown.
// WiFi and BLE never run at the same time — exclusive use, clean hand-off.

static void radio_silence_all() {
    // Stop every RF activity so the next mode starts from a known state.
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    WiFi.scanDelete();
    WiFi.disconnect(true, true);
    WiFi.mode(WIFI_OFF);
    if (ble_scan) {
        ble_scan->stop();
        ble_scan->clearResults();
    }
    if (ble_initialized) {
        BLEDevice::deinit(true);   // full teardown so WiFi can claim the radio
        ble_scan = nullptr;
        ble_initialized = false;
    }
    delay(100);
}

static void radio_setup_wifi() {
    radio_silence_all();
    // Prefer WiFi; coexistence APIs are not needed when BLE is fully off.
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, false);
    esp_wifi_start();
    delay(80);
}

static void radio_setup_ble() {
    radio_silence_all();
    // BLE only — WiFi is off so no coexistence conflict.
    if (!BLEDevice::init("")) {
        Serial.println("BLE init failed");
        return;
    }
    ble_scan = BLEDevice::getScan();
    if (!ble_scan) {
        Serial.println("BLE getScan failed");
        return;
    }
    ble_scan->setActiveScan(true);
    ble_scan->setInterval(100);
    ble_scan->setWindow(90);
    ble_initialized = true;
}

static void radio_teardown() {
    // Called when a radar exits (or before switching modes).
    if (ble_scan) {
        ble_scan->stop();
        ble_scan->clearResults();
    }
    WiFi.scanDelete();
    esp_wifi_set_promiscuous(false);
    WiFi.disconnect(true, true);
    WiFi.mode(WIFI_OFF);
    if (ble_initialized) {
        BLEDevice::deinit(true);
        ble_scan = nullptr;
        ble_initialized = false;
    }
    delay(80);
}

static void radar_push(const char* id, const char* name, int rssi, float yaw) {
    RadarHit h;
    memset(&h, 0, sizeof h);
    strncpy(h.id, id, sizeof(h.id) - 1);
    strncpy(h.name, name, sizeof(h.name) - 1);
    h.rssi = (int8_t)constrain(rssi, -127, 0);
    h.yaw  = yaw;
    if (radar_q) xQueueSend(radar_q, &h, 0);
}

static void radar_worker(void* arg) {
    const bool wifi = (arg != nullptr);
    while (radar_worker_run) {
        float y0 = radar_live_yaw;
        if (wifi) {
            int n = WiFi.scanNetworks(false, true, false, 60);
            float ym = (y0 + radar_live_yaw) * 0.5f;
            for (int i = 0; i < n; ++i)
                radar_push(WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str(), WiFi.RSSI(i), ym);
            WiFi.scanDelete();
        } else if (ble_scan) {
            BLEScanResults* res = ble_scan->start(1, false);
            float ym = (y0 + radar_live_yaw) * 0.5f;
            int n = res ? res->getCount() : -1;
            if (res) {
                for (int i = 0; i < n; ++i) {
                    BLEAdvertisedDevice d = res->getDevice(i);
                    String id = String(d.getAddress().toString().c_str());
                    String nm = d.haveName() ? String(d.getName().c_str()) : id.substring(0, 8);
                    radar_push(id.c_str(), nm.c_str(), d.getRSSI(), ym);
                }
                ble_scan->clearResults();
            }
            ble_scan->stop();
            vTaskDelay(pdMS_TO_TICKS(n < 0 ? 600 : 250));
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    radar_worker_alive = false;
    vTaskDelete(nullptr);
}

static void radar_worker_start(bool wifi) {
    if (!radar_q) radar_q = xQueueCreate(96, sizeof(RadarHit));
    xQueueReset(radar_q);
    radar_worker_run = true;
    radar_worker_alive = true;
    xTaskCreatePinnedToCore(radar_worker, "radar", 8192,
                            wifi ? (void*)1 : nullptr, 2, nullptr, 0);
}

static void radar_worker_stop() {
    radar_worker_run = false;
    uint32_t t0 = millis();
    while (radar_worker_alive && millis() - t0 < 4000) delay(20);
}

static void radar_drain() {
    RadarHit h;
    while (radar_q && xQueueReceive(radar_q, &h, 0) == pdTRUE)
        radar_sample(h.id, String(h.name), h.rssi, h.yaw);
}

// ---------------------------------------------------------------------------
//  Draw tiny mantis sprite at radar centre
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
//  Drawing
// ---------------------------------------------------------------------------
enum RadarPhase { RADAR_CAL, RADAR_MEASURE, RADAR_LIVE };

static M5Canvas* canvas = nullptr;

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

    if (ph == RADAR_MEASURE) {
        float cov = fminf(fabsf(green), 360.0f);
        if (cov > 1.0f)
            canvas->fillArc(CX, CY, R + 6, R + 3, 270.0f, 270.0f + cov, COL_TEAL);
        int x, y;
        at(fmodf(red, 360.0f), R, x, y);
        canvas->drawWideLine(CX, CY, x, y, 2.0f, COL_RED);
        at(fmodf(green + 3600.0f, 360.0f), R - 6, x, y);
        canvas->drawWideLine(CX, CY, x, y, 2.0f, COL_LIME);
    } else if (ph == RADAR_LIVE) {
        float sweep = fmodf(millis() * 0.18f, 360.0f);
        for (int t = 60; t >= 0; t -= 6) {
            int x, y;
            at(sweep - t, R, x, y);
            uint8_t v = (uint8_t)((63 - t) >> 1);
            // teal-ish fade
            uint16_t col = ((v >> 1) << 11) | ((v) << 5) | (v >> 2);
            canvas->drawLine(CX, CY, x, y, col);
        }
        canvas->fillTriangle(CX - 6, CY - R - 2, CX + 6, CY - R - 2,
                             CX, CY - R + 8, COL_TEAL);
    }

    float sweep_now = fmodf(millis() * 0.18f, 360.0f);
    for (int i = 0; i < radar_n; ++i) {
        RadarSource& d = radar_sources[i];
        float bearing = radar_peak_angle(d);
        float disp = (ph == RADAR_LIVE) ? bearing - heading : bearing;
        disp = fmodf(disp + 3600.0f, 360.0f);
        int x, y;
        at(disp, R * radar_range(d), x, y);
        bool lit = false;
        if (ph == RADAR_LIVE) {
            float da = fabsf(disp - sweep_now);
            if (da > 180) da = 360 - da;
            lit = da < 18.0f;
        }
        uint16_t col = lit ? COL_LIME
                           : (d.seen && millis() - d.seen < 3000 ? COL_TEAL : COL_DIM);
        canvas->fillCircle(x, y, lit ? 6 : 4, col);
    }

    // Mantis mascot sits in the very centre of the radar
    draw_mantis(canvas, CX, CY);

    canvas->setTextSize(1);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    canvas->setTextColor(COL_TEAL);
    canvas->drawString(wifi ? "WIFI RADAR" : "BLE RADAR", 4, 2);

    canvas->setTextDatum(top_right);
    canvas->setTextColor(COL_LIME);
    char nbuf[12];
    snprintf(nbuf, sizeof nbuf, "%d", radar_n);
    canvas->drawString(nbuf, 316, 2);

    canvas->setTextDatum(bottom_center);
    canvas->setTextColor(COL_HINT);
    const char* hint = ph == RADAR_CAL
        ? "hold still..."
        : ph == RADAR_MEASURE
            ? (green < -25.0f ? "other way!" : "turn: green on red")
            : "A=rescan  C=exit";
    canvas->drawString(hint, 160, 238);

    canvas->pushSprite(0, 0);
}

// ---------------------------------------------------------------------------
//  Input
// ---------------------------------------------------------------------------
static bool btn_exit() {
    if (M5.BtnC.wasClicked() || M5.BtnC.wasHold()) return true;
    if (M5.BtnA.wasHold()) return true;
    auto t = M5.Touch.getDetail();
    if (t.wasClicked() && t.y > 200) return true;
    return false;
}

static bool btn_action() {
    if (M5.BtnA.wasClicked()) return true;
    auto t = M5.Touch.getDetail();
    if (t.wasClicked() && t.y < 180) return true;
    return false;
}

static bool btn_next() {
    return M5.BtnB.wasClicked();
}

// ---------------------------------------------------------------------------
//  Radar run
// ---------------------------------------------------------------------------
static void radar_run(bool wifi) {
    for (;;) {
        radar_reset();

        // Each mode sets up its own radio exclusively, then tears it down on exit.
        if (wifi) radio_setup_wifi();
        else      radio_setup_ble();

        radar_draw(0, 0, wifi, RADAR_CAL, 0);
        RadarHeading hd;
        radar_heading_calibrate(hd);
        radar_worker_start(wifi);

        const float TARGET_DPS = 18.0f;
        uint32_t t0 = millis();
        bool quit = false;
        float green = 0;
        for (;;) {
            uint32_t f0 = millis();
            M5.update();
            if (btn_exit()) { quit = true; break; }
            green = radar_heading_update(hd);
            radar_live_yaw = green;
            radar_drain();
            float red = fminf(360.0f, (millis() - t0) * 0.001f * TARGET_DPS);
            radar_draw(green, red, wifi, RADAR_MEASURE, 0);
            if (fabsf(green) >= 360.0f) break;
            if (millis() - t0 > 60000) break;
            uint32_t el = millis() - f0;
            if (el < 30) delay(30 - el);
        }
        if (quit) {
            radar_worker_stop();
            radio_teardown();
            return;
        }

        hd.yaw = fmodf(hd.yaw, 360.0f);
        radar_draw(green, 360, wifi, RADAR_LIVE, hd.yaw);
        hd.last_us = micros();

        bool rescan = false;
        for (;;) {
            uint32_t f0 = millis();
            M5.update();
            if (btn_exit()) { quit = true; break; }
            if (btn_action()) { rescan = true; break; }
            float h = radar_heading_update(hd);
            radar_live_yaw = h;
            radar_drain();
            radar_draw(0, 0, wifi, RADAR_LIVE, h);
            uint32_t el = millis() - f0;
            if (el < 33) delay(33 - el);
        }
        radar_worker_stop();
        radio_teardown();   // always tear down so the other mode can claim the radio cleanly
        if (quit || !rescan) return;
        // rescan: loop again; setup runs at the top of the next iteration
    }
}

// ---------------------------------------------------------------------------
//  Splash + menu
// ---------------------------------------------------------------------------
static void draw_splash() {
    M5.Display.fillScreen(COL_BG);
    // simple geometric splash with title (sprite is tiny; title does the work)
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
    M5.Display.drawString("Core2  ·  M5Unified", 160, 180);
    // draw tiny mantis
    for (int y = 0; y < MANTIS_H; ++y)
        for (int x = 0; x < MANTIS_W; ++x) {
            int idx = y * MANTIS_W + x;
            if (!mantis_alpha[idx]) continue;
            M5.Display.drawPixel(160 - MANTIS_W/2 + x, 50 - MANTIS_H/2 + y, mantis_rgb565[idx]);
        }
    delay(1800);
}

static void draw_menu(int sel) {
    M5.Display.fillScreen(COL_BG);
    M5.Display.setTextDatum(top_center);
    M5.Display.setTextColor(COL_TEAL);
    M5.Display.setFont(&fonts::Font4);
    M5.Display.drawString("DeviceRadar", 160, 12);

    M5.Display.setFont(&fonts::Font0);
    M5.Display.setTextColor(COL_PURPLE);
    M5.Display.drawString("MANTIS", 160, 48);

    M5.Display.setFont(&fonts::Font2);
    M5.Display.setTextDatum(middle_center);

    auto item = [&](int idx, const char* label, int y) {
        bool on = (sel == idx);
        uint16_t bg = on ? COL_TEAL : COL_PANEL;
        uint16_t fg = on ? COL_BG : COL_TEXT;
        M5.Display.fillRoundRect(40, y - 22, 240, 44, 8, bg);
        if (on) M5.Display.drawRoundRect(40, y - 22, 240, 44, 8, COL_LIME);
        M5.Display.setTextColor(fg);
        M5.Display.drawString(label, 160, y);
    };

    item(0, "WiFi Radar", 105);
    item(1, "BLE Radar",  165);

    M5.Display.setTextDatum(bottom_center);
    M5.Display.setTextColor(COL_HINT);
    M5.Display.setFont(&fonts::Font0);
    M5.Display.drawString("A = select   B = next   C = power off", 160, 230);
}

static void menu_loop() {
    int sel = 0;
    draw_menu(sel);
    for (;;) {
        M5.update();
        if (btn_next()) {
            sel = (sel + 1) % 2;
            draw_menu(sel);
        }
        if (btn_action()) {
            radar_run(sel == 0);
            draw_menu(sel);
        }
        if (M5.BtnC.wasHold()) {
            M5.Power.powerOff();
        }
        delay(20);
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

    canvas = new M5Canvas(&M5.Display);
    canvas->createSprite(320, 240);
    canvas->setColorDepth(16);

    CX = 160; CY = 120; R = 95;

    Serial.begin(115200);
    Serial.println("DeviceRadar (Mantis) ready");

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

    draw_splash();
    menu_loop();
}

void loop() {
    delay(1000);
}
