/**
 * wifi_id.h — passive WiFi AP fingerprinting
 *
 * From a normal ESP32 scan (no association, no probe tricks beyond
 * show_hidden): SSID, BSSID, OUI vendor, channel, auth mode, RSSI,
 * hidden flag, and device-class from SSID/OUI patterns.
 */
#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <string.h>
#include <stdio.h>

struct OuiEntry { uint32_t oui; const char* name; };

// Overlap with BLE OUI table + common AP / camera / ISP silicon vendors
static const OuiEntry kWifiOuis[] = {
    {0x00037F, "Qualcomm Atheros"},
    {0x000C43, "Ralink"},
    {0x001018, "Broadcom"},
    {0x001A11, "Google"},
    {0x001B11, "Google"},
    {0x001D6B, "Amazon"},
    {0x001E58, "Sony"},
    {0x001EC2, "Apple"},
    {0x002241, "Espressif"},
    {0x0022F5, "Apple"},
    {0x002436, "Apple"},
    {0x0024D7, "Espressif"},
    {0x0025BC, "Apple"},
    {0x0026BB, "Apple"},
    {0x0026F2, "Netgear"},
    {0x003EE1, "Apple"},
    {0x004096, "Cisco Aironet"},
    {0x0050F2, "Microsoft"},
    {0x0078CD, "Samsung"},
    {0x00A0C6, "Qualcomm"},
    {0x00B0D0, "Dell"},
    {0x00D0B7, "Apple"},
    {0x00F76F, "Apple"},
    {0x0404EA, "Espressif"},
    {0x041E64, "Apple"},
    {0x046273, "Cisco"},
    {0x080028, "Amazon"},
    {0x0C4DE9, "Apple"},
    {0x0CFE5D, "Espressif"},
    {0x14CC20, "TP-Link"},
    {0x18B430, "Nest"},
    {0x1C5CF2, "Apple"},
    {0x20A6CD, "Apple"},
    {0x246F28, "Espressif"},
    {0x28107B, "Samsung"},
    {0x28E455, "Espressif"},
    {0x2C4D54, "Espressif"},
    {0x30AEA4, "Espressif"},
    {0x341298, "Apple"},
    {0x3C15C2, "Apple"},
    {0x3C6A9D, "Espressif"},
    {0x3CEF8C, "Samsung"},
    {0x484D7E, "Google"},
    {0x4C74BF, "Apple"},
    {0x500291, "Espressif"},
    {0x5433CB, "Apple"},
    {0x5CCF7F, "Espressif"},
    {0x600194, "Espressif"},
    {0x685B35, "Apple"},
    {0x68C63A, "Espressif"},
    {0x6C1DEB, "Espressif"},
    {0x7085C2, "Espressif"},
    {0x7831C1, "Apple"},
    {0x7C9EBD, "Espressif"},
    {0x84F3EB, "Espressif"},
    {0x88E9FE, "Apple"},
    {0x8CAAB5, "Espressif"},
    {0xA4CF12, "Espressif"},
    {0xAC67B2, "Espressif"},
    {0xB0B98A, "Amazon"},
    {0xB4E62D, "Espressif"},
    {0xB41E52, "Flock Safety"},
    {0xB8F009, "Espressif"},
    {0xC46E1F, "Espressif"},
    {0xC83A35, "Espressif"},
    {0xCC50E3, "Espressif"},
    {0xD0CF5E, "Espressif"},
    {0xD8A01D, "Espressif"},
    {0xDC4F22, "Espressif"},
    {0xE09806, "Espressif"},
    {0xE0E2E6, "Espressif"},
    {0xE8DB84, "Espressif"},
    {0xF008D1, "Espressif"},
    {0xF4CFA2, "Espressif"},
    {0xFC01C6, "Espressif"},
    // Ubiquiti / TP-Link / common router silicon
    {0x24A43C, "Ubiquiti"},
    {0x44D9E7, "Ubiquiti"},
    {0x788A20, "Ubiquiti"},
    {0x802AA8, "Ubiquiti"},
    {0xFCECDA, "Ubiquiti"},
    {0x50C7BF, "TP-Link"},
    {0x98DAC4, "TP-Link"},
    {0xC006C3, "TP-Link"},
    {0xE8DE27, "TP-Link"},
    {0x0018E7, "TP-Link"},
    {0x00E04C, "Realtek"},
    {0x001346, "Ralink"},
};
static constexpr int kWifiOuiCount = sizeof(kWifiOuis) / sizeof(kWifiOuis[0]);

static const char* wifi_oui_name(uint32_t oui) {
    oui &= 0xFFFFFF;
    for (int i = 0; i < kWifiOuiCount; ++i)
        if (kWifiOuis[i].oui == oui) return kWifiOuis[i].name;
    return nullptr;
}

static uint32_t wifi_bssid_oui(const char* bssid) {
    unsigned a=0,b=0,c=0;
    if (sscanf(bssid, "%2x:%2x:%2x", &a, &b, &c) != 3) return 0;
    return ((uint32_t)a << 16) | ((uint32_t)b << 8) | (uint32_t)c;
}

static bool wifi_name_has(const char* n, const char* sub) {
    if (!n || !sub) return false;
    for (const char* p = n; *p; ++p) {
        const char *a = p, *b = sub;
        while (*a && *b) {
            char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
            char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
            if (ca != cb) break;
            ++a; ++b;
        }
        if (!*b) return true;
    }
    return false;
}

static const char* wifi_auth_name(uint8_t enc) {
    switch (enc) {
        case WIFI_AUTH_OPEN: return "open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-EAP";
#ifdef WIFI_AUTH_WPA3_PSK
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
#endif
#ifdef WIFI_AUTH_WPA2_WPA3_PSK
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
#endif
#ifdef WIFI_AUTH_WAPI_PSK
        case WIFI_AUTH_WAPI_PSK: return "WAPI";
#endif
        default: return "sec?";
    }
}

struct WifiIdentity {
    char bssid[18];
    char ssid[33];
    char vendor[24];
    char kind[28];
    char detail[56];
    char device_class[32];
    int  rssi;
    int8_t channel;
    uint8_t encrypt;
    bool hidden;
};

static void wifi_classify(WifiIdentity& out) {
    const char* s = out.ssid;
    const char* v = out.vendor;
    const bool open = (out.encrypt == WIFI_AUTH_OPEN);
    const bool iot_oui = v && (strstr(v, "Espressif") || strstr(v, "Ralink") ||
                               strstr(v, "Realtek") || strstr(v, "Amazon") ||
                               strstr(v, "Flock") || strstr(v, "Nest"));

    // Soft-AP / setup mode (cameras & IoT often beacon open or weak while provisioning)
    // Classic ESP softAP: "ESP_XXXXXX" / "ESP32_XXXX"
    if (wifi_name_has(s, "esp_") || wifi_name_has(s, "esp32_") || wifi_name_has(s, "esp32-") ||
        wifi_name_has(s, "espressif")) {
        strncpy(out.device_class, open ? "ESP soft-AP (setup)" : "ESP32 AP",
                sizeof(out.device_class)-1);
        strncpy(out.kind, open ? "SoftAP open" : out.kind, sizeof(out.kind)-1);
        return;
    }
    // AI-Thinker / ESP32-CAM default SSIDs
    if (wifi_name_has(s, "ai-thinker") || wifi_name_has(s, "aithinker") ||
        wifi_name_has(s, "esp32-cam") || wifi_name_has(s, "esp32cam")) {
        strncpy(out.device_class, "ESP32-CAM soft-AP", sizeof(out.device_class)-1); return;
    }
    // Generic "setup" / "config" / "install" soft APs
    if (wifi_name_has(s, "setup") || wifi_name_has(s, "config") || wifi_name_has(s, "install") ||
        wifi_name_has(s, "pairing") || wifi_name_has(s, "provision") ||
        wifi_name_has(s, "-ap") || wifi_name_has(s, "_ap") || wifi_name_has(s, " softap")) {
        if (iot_oui || open || wifi_name_has(s, "cam") || wifi_name_has(s, "camera")) {
            strncpy(out.device_class, "Device setup SoftAP", sizeof(out.device_class)-1);
            return;
        }
    }
    // Open + IoT OUI = very likely soft-AP or misconfigured camera/sensor
    if (open && iot_oui) {
        strncpy(out.device_class, "Open IoT SoftAP", sizeof(out.device_class)-1); return;
    }

    // Cameras / surveillance — SSID patterns first (strong)
    if (wifi_name_has(s, "ring") && (wifi_name_has(s, "cam") || wifi_name_has(s, "door") ||
        wifi_name_has(s, "stick") || wifi_name_has(s, "flood") || wifi_name_has(s, "chime"))) {
        strncpy(out.device_class, "Ring camera", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "ring-") || wifi_name_has(s, "ring_")) {
        strncpy(out.device_class, "Ring device", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "flock") || wifi_name_has(s, "penguin")) {
        strncpy(out.device_class, "Flock Safety gear", sizeof(out.device_class)-1); return;
    }
    if (v && strstr(v, "Flock")) {
        strncpy(out.device_class, "Flock Safety camera", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "wyz") || wifi_name_has(s, "arlo") || wifi_name_has(s, "blink") ||
        wifi_name_has(s, "reolink") || wifi_name_has(s, "amcrest") ||
        wifi_name_has(s, "nest-cam") || wifi_name_has(s, "nest cam") ||
        wifi_name_has(s, "hikvision") || wifi_name_has(s, "dahua") ||
        wifi_name_has(s, "axis-") || wifi_name_has(s, "foscam")) {
        strncpy(out.device_class, "Security camera", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "esp32") || wifi_name_has(s, "esp-") || wifi_name_has(s, "espressif") ||
        (v && strstr(v, "Espressif"))) {
        if (wifi_name_has(s, "cam") || wifi_name_has(s, "camera"))
            strncpy(out.device_class, "ESP32 camera", sizeof(out.device_class)-1);
        else
            strncpy(out.device_class, "ESP32 / IoT AP", sizeof(out.device_class)-1);
        return;
    }
    if (wifi_name_has(s, "camera") || wifi_name_has(s, "ipcam") || wifi_name_has(s, "webcam")) {
        strncpy(out.device_class, "Camera", sizeof(out.device_class)-1); return;
    }
    // More camera / doorbell / NVR soft-AP and product SSIDs
    if (wifi_name_has(s, "doorbell") || wifi_name_has(s, "door-bell") ||
        wifi_name_has(s, "wyze-cam") || wifi_name_has(s, "wyze_setup") ||
        wifi_name_has(s, "arlo-cam") || wifi_name_has(s, "arlo_setup") ||
        wifi_name_has(s, "blink-") || wifi_name_has(s, "blinksetup") ||
        wifi_name_has(s, "eufy") || wifi_name_has(s, "tapo") ||
        wifi_name_has(s, "kasa") || wifi_name_has(s, "g3-flex") ||
        wifi_name_has(s, "g4-") || wifi_name_has(s, "unifi-cam") ||
        wifi_name_has(s, "ubnt") || wifi_name_has(s, "protect")) {
        strncpy(out.device_class, "Camera / doorbell AP", sizeof(out.device_class)-1); return;
    }
    // Android WiFi Direct / SoftAP naming
    if (wifi_name_has(s, "direct-") || wifi_name_has(s, "androidshare") ||
        wifi_name_has(s, "hotspot")) {
        strncpy(out.device_class, "Phone / SoftAP hotspot", sizeof(out.device_class)-1); return;
    }

    // Axon / bodycam (rare on WiFi but SSID setups exist)
    if (wifi_name_has(s, "axon") || wifi_name_has(s, "bodycam") || wifi_name_has(s, "body-worn")) {
        strncpy(out.device_class, "Axon / bodycam net", sizeof(out.device_class)-1); return;
    }

    // Phones as hotspots
    if (wifi_name_has(s, "iphone") || wifi_name_has(s, "ipad") || wifi_name_has(s, "androidap") ||
        wifi_name_has(s, "galaxy") || wifi_name_has(s, "pixel ") || wifi_name_has(s, "oneplus") ||
        wifi_name_has(s, "huawei") || wifi_name_has(s, "direct-") /* WiFi Direct */) {
        strncpy(out.device_class, "Phone hotspot", sizeof(out.device_class)-1); return;
    }
    if (v && strstr(v, "Apple") && (out.encrypt == WIFI_AUTH_OPEN || wifi_name_has(s, "iPhone"))) {
        // Apple often uses random-ish hotspot names; OUI still Apple
        if (wifi_name_has(s, "iphone") || wifi_name_has(s, "ipad"))
            strncpy(out.device_class, "Apple hotspot", sizeof(out.device_class)-1);
    }

    // Printers / IoT appliances
    if (wifi_name_has(s, "hp-") || wifi_name_has(s, "epson") || wifi_name_has(s, "canon") ||
        wifi_name_has(s, "brother") || wifi_name_has(s, "printer")) {
        strncpy(out.device_class, "Printer", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "roku") || wifi_name_has(s, "firetv") || wifi_name_has(s, "chromecast") ||
        wifi_name_has(s, "apple tv") || wifi_name_has(s, "shield")) {
        strncpy(out.device_class, "Streaming stick / TV", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "sonos") || wifi_name_has(s, "bose") || wifi_name_has(s, "homepod") ||
        wifi_name_has(s, "echo-") || wifi_name_has(s, "google-home") || wifi_name_has(s, "nest-audio")) {
        strncpy(out.device_class, "Smart speaker", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "tesla")) {
        strncpy(out.device_class, "Tesla", sizeof(out.device_class)-1); return;
    }

    // Routers / mesh by OUI or SSID
    if (v && (strstr(v, "Ubiquiti") || strstr(v, "TP-Link") || strstr(v, "Netgear") ||
              strstr(v, "Cisco") || strstr(v, "Ralink") || strstr(v, "Realtek"))) {
        strncpy(out.device_class, "Router / AP", sizeof(out.device_class)-1); return;
    }
    if (wifi_name_has(s, "eero") || wifi_name_has(s, "orbi") || wifi_name_has(s, "google wifi") ||
        wifi_name_has(s, "nest wifi") || wifi_name_has(s, "asus") || wifi_name_has(s, "linksys") ||
        wifi_name_has(s, "xfinity") || wifi_name_has(s, "att") || wifi_name_has(s, "verizon")) {
        strncpy(out.device_class, "Router / mesh", sizeof(out.device_class)-1); return;
    }

    // Amazon devices
    if (v && strstr(v, "Amazon")) {
        strncpy(out.device_class, "Amazon device", sizeof(out.device_class)-1); return;
    }
    if (v && strstr(v, "Google") || wifi_name_has(s, "google")) {
        strncpy(out.device_class, "Google device", sizeof(out.device_class)-1); return;
    }
    if (v && strstr(v, "Nest")) {
        strncpy(out.device_class, "Nest device", sizeof(out.device_class)-1); return;
    }
    if (v && strstr(v, "Apple")) {
        strncpy(out.device_class, "Apple device", sizeof(out.device_class)-1); return;
    }
    if (v && strstr(v, "Samsung")) {
        strncpy(out.device_class, "Samsung device", sizeof(out.device_class)-1); return;
    }

    // Open AP note
    if (out.encrypt == WIFI_AUTH_OPEN) {
        strncpy(out.device_class, "Open AP", sizeof(out.device_class)-1); return;
    }

    if (v && v[0] && v[0] != '-') {
        snprintf(out.device_class, sizeof(out.device_class), "%s AP", v);
    } else {
        strncpy(out.device_class, "WiFi AP", sizeof(out.device_class)-1);
    }
}

static void wifi_identify(int scan_index, WifiIdentity& out) {
    memset(&out, 0, sizeof out);
    String bssid = WiFi.BSSIDstr(scan_index);
    String ssid  = WiFi.SSID(scan_index);
    strncpy(out.bssid, bssid.c_str(), sizeof(out.bssid)-1);
    if (ssid.length())
        strncpy(out.ssid, ssid.c_str(), sizeof(out.ssid)-1);
    else {
        strncpy(out.ssid, "(hidden)", sizeof(out.ssid)-1);
        out.hidden = true;
    }
    out.rssi = WiFi.RSSI(scan_index);
    out.channel = (int8_t)WiFi.channel(scan_index);
    out.encrypt = (uint8_t)WiFi.encryptionType(scan_index);

    uint32_t oui = wifi_bssid_oui(out.bssid);
    const char* on = wifi_oui_name(oui);
    if (on) strncpy(out.vendor, on, sizeof(out.vendor)-1);
    else if (oui)
        snprintf(out.vendor, sizeof(out.vendor), "OUI %06X", oui);
    else
        strncpy(out.vendor, "—", sizeof(out.vendor)-1);

    // kind = short radio summary
    snprintf(out.kind, sizeof(out.kind), "ch%d 2.4G %s", (int)out.channel, wifi_auth_name(out.encrypt));

    // detail = BSSID + band hint
    const char* band = (out.channel >= 36) ? "5GHz" : "2.4GHz";
    snprintf(out.detail, sizeof(out.detail), "%s %s %s",
             out.bssid, band, out.hidden ? "hidden" : "");

    wifi_classify(out);
}
