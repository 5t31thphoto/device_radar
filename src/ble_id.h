/**
 * ble_id.h — passive BLE fingerprinting (exhaustive AD use)
 *
 * Uses every field the Arduino-ESP32 scanner exposes without connecting:
 *   MAC + address type, IEEE OUI (public MACs), local name,
 *   manufacturer data + company ID + vendor patterns,
 *   full raw AD walk (UUID lists, service data, flags, mfr),
 *   appearance, TX power, service UUIDs, service data.
 * Optional SD /ble_ids.txt extends company/service name tables.
 */
#pragma once
#include <Arduino.h>
#include <BLEAdvertisedDevice.h>
#include <string.h>
#include <stdio.h>
#include <SPI.h>
#include <SD.h>

struct CoId  { uint16_t id;   const char* name; };
struct SvcId { uint16_t uuid; const char* name; };
struct OuiId { uint32_t oui;  const char* name; };

static const CoId kCompanyIds[] = {
    {0x0000, "Ericsson"},
    {0x0001, "Nokia"},
    {0x0002, "Intel"},
    {0x0003, "IBM"},
    {0x0004, "Toshiba"},
    {0x0005, "3Com"},
    {0x0006, "Microsoft"},
    {0x0007, "Lucent"},
    {0x0008, "Motorola"},
    {0x0009, "Infineon"},
    {0x000A, "Qualcomm QTIL"},
    {0x000B, "Silicon Wave"},
    {0x000C, "Digianswer"},
    {0x000D, "Texas Instruments"},
    {0x000E, "Parthus"},
    {0x000F, "Broadcom"},
    {0x0010, "Mitel"},
    {0x0011, "Widcomm"},
    {0x0012, "Zeevo"},
    {0x0013, "Atmel"},
    {0x0014, "Mitsubishi"},
    {0x0015, "RTX"},
    {0x0016, "KC Technology"},
    {0x0017, "NewLogic"},
    {0x0018, "Transilica"},
    {0x0019, "Rohde & Schwarz"},
    {0x001A, "TTPCom"},
    {0x001B, "Signia"},
    {0x001C, "Conexant"},
    {0x001D, "Qualcomm"},
    {0x001E, "Inventel"},
    {0x001F, "AVM Berlin"},
    {0x0020, "BandSpeed"},
    {0x0021, "Mansella"},
    {0x0022, "NEC"},
    {0x0023, "WavePlus"},
    {0x0024, "Alcatel"},
    {0x0025, "NXP Semiconductors"},
    {0x0026, "C Technologies"},
    {0x0027, "Open Interface"},
    {0x0028, "R F Micro Devices"},
    {0x0029, "Hitachi"},
    {0x002A, "Symbol Technologies"},
    {0x002B, "Tenovis"},
    {0x002C, "Macronix"},
    {0x002D, "GCT Semiconductor"},
    {0x002E, "Norwood Microsystems"},
    {0x002F, "MewTel Technology"},
    {0x0030, "ST Microelectronics"},
    {0x0031, "Synopsys"},
    {0x0032, "Red-M"},
    {0x0033, "Commil"},
    {0x0034, "Catena Networks"},
    {0x0035, "Integrated System Solution"},
    {0x0036, "Renesas"},
    {0x0037, "Invision Technologies"},
    {0x0038, "ISSC Technologies"},
    {0x0039, "Plantronics"},
    {0x003A, "Nomadio"},
    {0x003B, "Gennum"},
    {0x003C, "MobileComm"},
    {0x003D, "IPextreme"},
    {0x003E, "Systems and Chips"},
    {0x003F, "Bluetooth SIG"},
    {0x0040, "Seiko Epson"},
    {0x0041, "Integrated Silicon Solution"},
    {0x0042, "CONWISE"},
    {0x0043, "PARROT"},
    {0x0044, "Socket Mobile"},
    {0x0045, "Atheros"},
    {0x0046, "MediaTek"},
    {0x0047, "Bluegiga"},
    {0x0048, "Marvell"},
    {0x0049, "3DSP"},
    {0x004A, "Accel Semiconductor"},
    {0x004B, "Continental Automotive"},
    {0x004C, "Apple"},
    {0x004D, "Staccato"},
    {0x004E, "Avago"},
    {0x004F, "APT"},
    {0x0050, "SiRF"},
    {0x0051, "Tzero"},
    {0x0052, "J&M"},
    {0x0053, "Free2move"},
    {0x0054, "3Di"},
    {0x0055, "Planet Communication"},
    {0x0056, "HP"},
    {0x0057, "Ralink"},
    {0x0058, "RDA"},
    {0x0059, "Nordic Semiconductor"},
    {0x005A, "EM Microelectronic"},
    {0x005B, "Ralink"},
    {0x005C, "Belkin"},
    {0x005D, "Realtek"},
    {0x005E, "Stonestreet One"},
    {0x005F, "Wicentric"},
    {0x0060, "Rivada Networks"},
    {0x0061, "Delphi"},
    {0x0062, "TiVo"},
    {0x0063, "Sennheiser"},
    {0x0064, "Summit Data"},
    {0x0065, "BLU"},
    {0x0067, "A&D Engineering"},
    {0x0068, "General Motors"},
    {0x0069, "UD Technology"},
    {0x006A, "Maxon"},
    {0x006B, "Cambridge Silicon Radio"},
    {0x006C, "Seiko Instruments"},
    {0x006D, "Shenzhen Goodix"},
    {0x006E, "Rafael Microelectronics"},
    {0x006F, "Quest Engineering"},
    {0x0070, "Dongguan YX"},
    {0x0075, "Samsung Electronics"},
    {0x0076, "Creative Technology"},
    {0x0077, "Laird Connectivity"},
    {0x0078, "Nike"},
    {0x0079, "lesswire"},
    {0x007A, "MStar Semiconductor"},
    {0x007B, "Hanlynn Technologies"},
    {0x007C, "A&R Cambridge"},
    {0x007D, "Seers Technology"},
    {0x007E, "Sports Tracking Technologies"},
    {0x007F, "Autonet Mobile"},
    {0x0080, "DeLorme Publishing"},
    {0x0081, "WuXi Vimicro"},
    {0x0082, "Sennheiser Communications"},
    {0x0083, "TimeKeeping Systems"},
    {0x0084, "Ludus Helsinki"},
    {0x0085, "BlueRadios"},
    {0x0086, "Equinux"},
    {0x0087, "Garmin"},
    {0x0088, "Ecotest"},
    {0x0089, "GN ReSound"},
    {0x008A, "Jawbone"},
    {0x008B, "Topcon Healthcare"},
    {0x008C, "Gimbal"},
    {0x008D, "GN Netcom"},
    {0x008E, "Schneider Electric"},
    {0x008F, "Trek"},
    {0x0090, "Tencent"},
    {0x0091, "Nordic UART"},
    {0x00D2, "Microsoft Band"},
    {0x00E0, "Google"},
    {0x0131, "Cypress Semiconductor"},
    {0x0157, "Anhui Huami"},
    {0x01D1, "OMRON"},
    {0x01FF, "Google"},
    {0x0201, "Dialog Semiconductor"},
    {0x02E5, "Espressif"},
    {0x0310, "Sennheiser Electronic"},
    {0x03C2, "Xiaomi"},
    {0x03DA, "EnOcean"},
    {0x0499, "Ruuvi Innovations"},
    {0x0500, "Wiliot"},
    {0x0528, "Garmin International"},
    {0x0583, "Code Blue Communications"},
    {0x05A7, "Sonos"},
    {0x05C1, "Tile"},
    {0x0601, "Bose"},
    {0x0639, "Minew Technologies"},
    {0x06D5, "Honor Device"},
    {0x0714, "OPPO"},
    {0x079A, "Huawei Technologies"},
    {0x0822, "Nothing Technology"},
    {0x08A9, "OnePlus Technology"},
    {0x0A62, "MOKO Technology"},
    {0x0B62, "vivo Mobile"},
    {0x0D28, "Fitbit"},
    {0x0F0E, "Oura Health"},
};
static constexpr int kCompanyIdCount = sizeof(kCompanyIds)/sizeof(kCompanyIds[0]);

static const SvcId kServices[] = {
    {0x1800, "Generic Access"},
    {0x1801, "Generic Attribute"},
    {0x1802, "Immediate Alert"},
    {0x1803, "Link Loss"},
    {0x1804, "Tx Power"},
    {0x1805, "Current Time"},
    {0x1806, "Reference Time Update"},
    {0x1807, "Next DST Change"},
    {0x1808, "Glucose"},
    {0x1809, "Health Thermometer"},
    {0x180A, "Device Information"},
    {0x180D, "Heart Rate"},
    {0x180E, "Phone Alert Status"},
    {0x180F, "Battery Service"},
    {0x1810, "Blood Pressure"},
    {0x1811, "Alert Notification"},
    {0x1812, "Human Interface Device"},
    {0x1813, "Scan Parameters"},
    {0x1814, "Running Speed and Cadence"},
    {0x1815, "Automation IO"},
    {0x1816, "Cycling Speed and Cadence"},
    {0x1818, "Cycling Power"},
    {0x1819, "Location and Navigation"},
    {0x181A, "Environmental Sensing"},
    {0x181B, "Body Composition"},
    {0x181C, "User Data"},
    {0x181D, "Weight Scale"},
    {0x181E, "Bond Management"},
    {0x181F, "Continuous Glucose Monitoring"},
    {0x1820, "Internet Protocol Support"},
    {0x1821, "Indoor Positioning"},
    {0x1822, "Pulse Oximeter"},
    {0x1823, "HTTP Proxy"},
    {0x1824, "Transport Discovery"},
    {0x1825, "Object Transfer"},
    {0x1826, "Fitness Machine"},
    {0x1827, "Mesh Provisioning"},
    {0x1828, "Mesh Proxy"},
    {0x1829, "Reconnection Configuration"},
    {0x183A, "Insulin Delivery"},
    {0x183B, "Binary Sensor"},
    {0x183C, "Emergency Configuration"},
    {0x183D, "Authorization Control"},
    {0x183E, "Physical Activity Monitor"},
    {0x1843, "Audio Stream Control"},
    {0x1844, "Broadcast Audio Scan"},
    {0x1845, "Published Audio Capabilities"},
    {0x1846, "Basic Audio Announcement"},
    {0x1847, "Broadcast Audio Announcement"},
    {0x1848, "Common Audio"},
    {0x1849, "Hearing Access"},
    {0x184A, "Telephony and Media Audio"},
    {0x184B, "Public Broadcast Announcement"},
    {0x184C, "Volume Control"},
    {0x184D, "Volume Offset Control"},
    {0x184E, "Coordinated Set Identification"},
    {0x184F, "Microphone Control"},
    {0x1850, "Audio Input Control"},
    {0x1851, "Telephone Bearer"},
    {0x1852, "Generic Telephone Bearer"},
    {0x1853, "Microphone Control"},
    {0x1854, "Audio Stream Control Point"},
    {0x1855, "Broadcast Audio Scan Control Point"},
    {0xFEAA, "Eddystone"},
    {0xFD6F, "Exposure Notification"},
    {0xFE2C, "Google Fast Pair"},
    {0xFE9F, "Google"},
    {0xFE95, "Xiaomi"},
    {0xFD5A, "Samsung"},
    {0xFD1D, "Samsung"},
    {0xFD22, "Huawei"},
    {0xFD21, "Huawei"},
    {0xFD36, "Google"},
    {0xFE59, "Nordic UART"},
};
static constexpr int kServiceCount = sizeof(kServices)/sizeof(kServices[0]);

static const OuiId kOuis[] = {
    {0x001A11, "Google"},
    {0x001D6B, "Amazon"},
    {0x001EC2, "Apple"},
    {0x002241, "Espressif"},
    {0x002436, "Apple"},
    {0x0025BC, "Apple"},
    {0x0026BB, "Apple"},
    {0x003EE1, "Apple"},
    {0x0050F2, "Microsoft"},
    {0x0078CD, "Samsung"},
    {0x00A0C6, "Qualcomm"},
    {0x00F76F, "Apple"},
    {0x0404EA, "Espressif"},
    {0x0C4DE9, "Apple"},
    {0x0CFE5D, "Espressif"},
    {0x18B430, "Nest"},
    {0x1C5CF2, "Apple"},
    {0x246F28, "Espressif"},
    {0x28107B, "Samsung"},
    {0x28E455, "Espressif"},
    {0x2C4D54, "Espressif"},
    {0x30AEA4, "Espressif"},
    {0x341298, "Apple"},
    {0x3C15C2, "Apple"},
    {0x3C6A9D, "Espressif"},
    {0x3CEF8C, "Samsung"},
    {0x4C74BF, "Apple"},
    {0x500291, "Espressif"},
    {0x5433CB, "Apple"},
    {0x5CCF7F, "Espressif"},
    {0x600194, "Espressif"},
    {0x685B35, "Apple"},
    {0x68C63A, "Espressif"},
    {0x7831C1, "Apple"},
    {0x7C9EBD, "Espressif"},
    {0x84F3EB, "Espressif"},
    {0x88E9FE, "Apple"},
    {0x8CAAB5, "Espressif"},
    {0xA4CF12, "Espressif"},
    {0xAC67B2, "Espressif"},
    {0xB4E62D, "Espressif"},
    {0xB41E52, "Flock Safety"},
    {0x00037F, "Qualcomm Atheros"},
    {0xC83A35, "Espressif"},
    {0xDC4F22, "Espressif"},
    {0xE0E2E6, "Espressif"},
    {0xFC01C6, "Espressif"},
};
static constexpr int kOuiCount = sizeof(kOuis)/sizeof(kOuis[0]);

// SD overrides
static constexpr int kSdCoMax = 256, kSdSvcMax = 128;
static CoId  kSdCompany[kSdCoMax]; static char kSdCoNames[kSdCoMax][28]; static int kSdCoCount = 0;
static SvcId kSdService[kSdSvcMax]; static char kSdSvcNames[kSdSvcMax][32]; static int kSdSvcCount = 0;
static bool kSdTried = false;

static void ble_id_load_sd() {
    if (kSdTried) return;
    kSdTried = true;
    File f = SD.open("/ble_ids.txt", FILE_READ);
    if (!f) f = SD.open("ble_ids.txt", FILE_READ);
    if (!f) return;
    while (f.available()) {
        String line = f.readStringUntil('\n'); line.trim();
        if (line.length() < 5 || line[0] == '#') continue;
        if (line.startsWith("C,") && kSdCoCount < kSdCoMax) {
            int c1 = line.indexOf(',', 2); if (c1 < 0) continue;
            uint16_t id = (uint16_t)strtoul(line.substring(2, c1).c_str(), nullptr, 16);
            line.substring(c1+1).toCharArray(kSdCoNames[kSdCoCount], 28);
            kSdCompany[kSdCoCount] = { id, kSdCoNames[kSdCoCount] }; kSdCoCount++;
        } else if (line.startsWith("S,") && kSdSvcCount < kSdSvcMax) {
            int c1 = line.indexOf(',', 2); if (c1 < 0) continue;
            uint16_t id = (uint16_t)strtoul(line.substring(2, c1).c_str(), nullptr, 16);
            line.substring(c1+1).toCharArray(kSdSvcNames[kSdSvcCount], 32);
            kSdService[kSdSvcCount] = { id, kSdSvcNames[kSdSvcCount] }; kSdSvcCount++;
        }
    }
    f.close();
    Serial.printf("ble_id SD: %d co, %d svc\n", kSdCoCount, kSdSvcCount);
}

static const char* company_name(uint16_t id) {
    ble_id_load_sd();
    for (int i = 0; i < kSdCoCount; ++i) if (kSdCompany[i].id == id) return kSdCompany[i].name;
    for (int i = 0; i < kCompanyIdCount; ++i) if (kCompanyIds[i].id == id) return kCompanyIds[i].name;
    return nullptr;
}
static const char* service_name(uint16_t u) {
    ble_id_load_sd();
    for (int i = 0; i < kSdSvcCount; ++i) if (kSdService[i].uuid == u) return kSdService[i].name;
    for (int i = 0; i < kServiceCount; ++i) if (kServices[i].uuid == u) return kServices[i].name;
    return nullptr;
}
static const char* oui_name(uint32_t oui) {
    oui &= 0xFFFFFF;
    for (int i = 0; i < kOuiCount; ++i) if (kOuis[i].oui == oui) return kOuis[i].name;
    return nullptr;
}
static uint32_t mac_to_oui(const char* addr) {
    unsigned a=0,b=0,c=0;
    if (sscanf(addr, "%2x:%2x:%2x", &a, &b, &c) != 3) return 0;
    return ((uint32_t)a << 16) | ((uint32_t)b << 8) | (uint32_t)c;
}

static const char* appearance_name(uint16_t a) {
    switch (a) {
        case 0x0040: return "Phone"; case 0x0080: return "Computer";
        case 0x00C0: return "Watch"; case 0x00C1: return "Sports Watch";
        case 0x0140: return "Display"; case 0x01C0: return "Eyewear";
        case 0x0240: return "Tag"; case 0x0280: return "Keyring";
        case 0x03C0: return "Media Player"; case 0x0440: return "Audio Card";
        case 0x0441: return "Headphones"; case 0x0442: return "Mic";
        case 0x0443: return "Headset"; case 0x0480: return "HID";
        case 0x04C0: return "Keyboard"; case 0x0500: return "Mouse";
        case 0x0C40: return "Blood Pressure"; case 0x0D40: return "Thermometer";
        case 0x0DA0: return "Heart Rate"; case 0x0F00: return "Running";
        case 0x0F80: return "Cycling"; case 0x1440: return "Pulse Oximeter";
        case 0x1480: return "Weight Scale"; default: return nullptr;
    }
}
static const char* addr_type_name(uint8_t t) {
    switch (t) {
        case 0: return "Public"; case 1: return "Random";
        case 2: return "RPA Public"; case 3: return "RPA Random";
        default: return "Addr?";
    }
}

struct BleIdentity {
    char addr[18];
    char addr_type[12];
    char name[28];
    char vendor[24];
    char kind[28];
    char detail[56];
    char device_class[32];
    int  rssi;
    uint16_t company_id;
    bool is_ibeacon;
    bool is_random_mac;
};

static bool name_has(const char* n, const char* sub) {
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

static void parse_raw_ad(const uint8_t* payload, size_t plen, BleIdentity& out) {
    if (!payload || plen < 2) return;
    size_t i = 0;
    while (i + 1 < plen) {
        uint8_t len = payload[i];
        if (len == 0) break;
        if (i + 1 + len > plen) break;
        uint8_t type = payload[i + 1];
        const uint8_t* data = payload + i + 2;
        uint8_t dlen = len - 1;

        // 16-bit UUID lists (incomplete/complete)
        if ((type == 0x02 || type == 0x03) && dlen >= 2) {
            for (uint8_t off = 0; off + 1 < dlen; off += 2) {
                uint16_t u = (uint16_t)data[off] | ((uint16_t)data[off+1] << 8);
                const char* sn = service_name(u);
                if (u == 0xFEAA) strncpy(out.kind, "Eddystone", sizeof(out.kind)-1);
                else if (u == 0xFD6F) strncpy(out.kind, "Exposure Notif", sizeof(out.kind)-1);
                else if (u == 0xFE2C) strncpy(out.kind, "Fast Pair", sizeof(out.kind)-1);
                else if (u == 0xFD5A) strncpy(out.kind, "Samsung SmartTag svc", sizeof(out.kind)-1);
                else if (sn && (!out.kind[0] || !strcmp(out.kind, "BLE device")))
                    strncpy(out.kind, sn, sizeof(out.kind)-1);
                else if (!out.detail[0])
                    snprintf(out.detail, sizeof(out.detail), "uuid %04X", u);
            }
        }
        // 128-bit UUID complete/incomplete — note presence
        if ((type == 0x06 || type == 0x07) && dlen >= 16 && !out.detail[0]) {
            snprintf(out.detail, sizeof(out.detail), "uuid128 %uB", dlen);
        }
        // Service data 16-bit
        if (type == 0x16 && dlen >= 2) {
            uint16_t u = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
            if (u == 0xFEAA) strncpy(out.kind, "Eddystone", sizeof(out.kind)-1);
            if (u == 0xFD6F) strncpy(out.kind, "Exposure Notif", sizeof(out.kind)-1);
            if (u == 0xFD5A) strncpy(out.kind, "Samsung SmartTag svc", sizeof(out.kind)-1);
            if (!out.detail[0])
                snprintf(out.detail, sizeof(out.detail), "svcdata %04X %uB", u, dlen);
        }
        // Service data 128-bit
        if (type == 0x21 && dlen >= 16 && !out.detail[0]) {
            snprintf(out.detail, sizeof(out.detail), "svcdata128 %uB", dlen);
        }
        // Flags
        if (type == 0x01 && dlen >= 1 && (data[0] & 0x01) && !out.detail[0])
            snprintf(out.detail, sizeof(out.detail), "flags limited");
        // Manufacturer (if library missed it)
        if (type == 0xFF && dlen >= 2 && out.company_id == 0xFFFF) {
            uint16_t cid = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
            out.company_id = cid;
            const char* cn = company_name(cid);
            if (cn) strncpy(out.vendor, cn, sizeof(out.vendor)-1);
            else snprintf(out.vendor, sizeof(out.vendor), "CID 0x%04X", cid);
        }
        // TX power
        if (type == 0x0A && dlen >= 1 && !out.detail[0])
            snprintf(out.detail, sizeof(out.detail), "tx %ddBm", (int)(int8_t)data[0]);
        // Appearance
        if (type == 0x19 && dlen >= 2 && !out.kind[0]) {
            uint16_t ap = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
            const char* an = appearance_name(ap);
            if (an) strncpy(out.kind, an, sizeof(out.kind)-1);
        }
        i += (size_t)len + 1;
    }
}

static void ble_classify(BleIdentity& out, const uint8_t* mfr, size_t mfr_len) {
    const char* n = out.name;
    uint16_t cid = out.company_id;
    uint8_t sub = (mfr && mfr_len >= 3) ? mfr[2] : 0xFF;

    // Keep strong OUI-based class if already set
    if (out.device_class[0] && strstr(out.device_class, "Flock")) return;

    if (cid == 0x004C && (sub == 0x12 || sub == 0x07)) {
        if (sub == 0x12) {
            strncpy(out.device_class, "AirTag / Find My tag", sizeof(out.device_class)-1);
            strncpy(out.kind, "Find My OF", sizeof(out.kind)-1); return;
        }
        if (name_has(n, "airtag") || out.is_random_mac) {
            strncpy(out.device_class, "AirTag (unreg/FindMy)", sizeof(out.device_class)-1); return;
        }
    }
    if (name_has(n, "airtag")) { strncpy(out.device_class, "AirTag", sizeof(out.device_class)-1); return; }
    if (cid == 0x00C7 || cid == 0x05C1 || name_has(n, "tile")) {
        strncpy(out.device_class, "Tile tracker", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "smarttag") || name_has(n, "galaxy smarttag") ||
        strstr(out.kind, "SmartTag")) {
        strncpy(out.device_class, "Samsung SmartTag", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x0075 && (name_has(n, "tag") || name_has(n, "tracker"))) {
        strncpy(out.device_class, "Samsung tracker", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "chipolo") || name_has(n, "pebblebee") || name_has(n, "moto tag")) {
        strncpy(out.device_class, "Tracker tag", sizeof(out.device_class)-1); return;
    }

    if (name_has(n, "ring") && (name_has(n, "cam") || name_has(n, "door") || name_has(n, "stick") ||
        name_has(n, "flood") || name_has(n, "spotlight"))) {
        strncpy(out.device_class, "Ring camera", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "ring ")) { strncpy(out.device_class, "Ring device", sizeof(out.device_class)-1); return; }
    if (name_has(n, "axon") || name_has(n, "ab3") || name_has(n, "ab4") ||
        name_has(n, "body_3") || name_has(n, "body_4") || name_has(n, "flex2")) {
        strncpy(out.device_class, "Axon bodycam", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "penguin-") || name_has(n, "fs ext battery") || name_has(n, "flock")) {
        strncpy(out.device_class, "Flock Safety gear", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x09C8) { strncpy(out.device_class, "Flock battery pack?", sizeof(out.device_class)-1); return; }

    if (cid == 0x02E5 || name_has(n, "esp32") || name_has(n, "esp-") ||
        name_has(n, "espressif") || name_has(n, "ai-thinker") || name_has(n, "esp32cam") ||
        strstr(out.kind, "Espressif") || (out.vendor[0] && strstr(out.vendor, "Espressif"))) {
        if (name_has(n, "cam") || name_has(n, "camera"))
            strncpy(out.device_class, "ESP32 camera", sizeof(out.device_class)-1);
        else
            strncpy(out.device_class, "ESP32 / Espressif", sizeof(out.device_class)-1);
        return;
    }
    if (name_has(n, "wyz") || name_has(n, "arlo") || name_has(n, "nest cam") ||
        name_has(n, "blink") || name_has(n, "reolink") || name_has(n, "amcrest")) {
        strncpy(out.device_class, "Security camera", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "camera") || name_has(n, "webcam") || name_has(n, "ipcam")) {
        strncpy(out.device_class, "Camera", sizeof(out.device_class)-1); return;
    }

    if (cid == 0x004C && sub == 0x07) {
        strncpy(out.device_class, "AirPods / Apple audio", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "airpods") || name_has(n, "beats ")) {
        strncpy(out.device_class, "Apple headphones", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "apple watch") || (name_has(n, "watch") && cid == 0x004C)) {
        strncpy(out.device_class, "Apple Watch", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x004C && (sub == 0x10 || sub == 0x0F || sub == 0x05 || sub == 0x0C)) {
        strncpy(out.device_class, "Apple phone/iPad nearby", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x004C && sub == 0x01) {
        strncpy(out.device_class, "Apple Handoff (phone/Mac)", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "iphone") || name_has(n, "ipad")) {
        strncpy(out.device_class, "Apple phone/tablet", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "galaxy") || name_has(n, "pixel ") || name_has(n, "oneplus") ||
        name_has(n, "xiaomi") || name_has(n, "redmi") || name_has(n, "huawei") ||
        name_has(n, "honor") || name_has(n, "oppo") || name_has(n, "vivo")) {
        strncpy(out.device_class, "Android phone", sizeof(out.device_class)-1); return;
    }
    if (strstr(out.kind, "Phone")) { strncpy(out.device_class, "Phone", sizeof(out.device_class)-1); return; }

    if (cid == 0x05A7 || name_has(n, "sonos")) {
        strncpy(out.device_class, "Sonos speaker", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x0601 || name_has(n, "bose")) {
        strncpy(out.device_class, "Bose speaker/headphones", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "jbl") || name_has(n, "homepod") || name_has(n, "echo ") ||
        name_has(n, "alexa") || name_has(n, "google home") || name_has(n, "nest mini")) {
        strncpy(out.device_class, "Smart speaker", sizeof(out.device_class)-1); return;
    }
    if (strstr(out.kind, "Headphones") || strstr(out.kind, "Headset")) {
        strncpy(out.device_class, "Headphones / audio", sizeof(out.device_class)-1); return;
    }

    if (name_has(n, "fitbit") || cid == 0x0D28) {
        strncpy(out.device_class, "Fitbit", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "garmin") || cid == 0x0087 || cid == 0x0528) {
        strncpy(out.device_class, "Garmin watch/tracker", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "amazfit") || name_has(n, "mi band") || cid == 0x0157) {
        strncpy(out.device_class, "Fitness band", sizeof(out.device_class)-1); return;
    }
    if (name_has(n, "oura") || cid == 0x0F0E) {
        strncpy(out.device_class, "Oura ring", sizeof(out.device_class)-1); return;
    }
    if (strstr(out.kind, "Watch") || strstr(out.kind, "Heart Rate") || strstr(out.kind, "Fitness")) {
        strncpy(out.device_class, "Wearable / fitness", sizeof(out.device_class)-1); return;
    }

    if (name_has(n, "tesla")) { strncpy(out.device_class, "Car / key fob", sizeof(out.device_class)-1); return; }
    if (strstr(out.kind, "Keyboard") || strstr(out.kind, "Mouse") || strstr(out.kind, "HID")) {
        strncpy(out.device_class, "Keyboard / mouse", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x0006) { strncpy(out.device_class, "Microsoft device", sizeof(out.device_class)-1); return; }
    if (strstr(out.kind, "Fast Pair")) {
        strncpy(out.device_class, "Android accessory (Fast Pair)", sizeof(out.device_class)-1); return;
    }
    if (strstr(out.kind, "Eddystone")) {
        strncpy(out.device_class, "Eddystone beacon", sizeof(out.device_class)-1); return;
    }
    if (strstr(out.kind, "Exposure")) {
        strncpy(out.device_class, "Exposure Notification", sizeof(out.device_class)-1); return;
    }
    if (out.is_ibeacon) { strncpy(out.device_class, "iBeacon", sizeof(out.device_class)-1); return; }

    if (cid == 0x004C) { strncpy(out.device_class, "Apple device", sizeof(out.device_class)-1); return; }
    if (cid == 0x0075) { strncpy(out.device_class, "Samsung device", sizeof(out.device_class)-1); return; }
    if (cid == 0x00E0 || cid == 0x01FF) {
        strncpy(out.device_class, "Google device", sizeof(out.device_class)-1); return;
    }
    if (cid == 0x03C2) { strncpy(out.device_class, "Xiaomi device", sizeof(out.device_class)-1); return; }
    if (cid == 0x0059) { strncpy(out.device_class, "Nordic BLE module", sizeof(out.device_class)-1); return; }

    if (out.vendor[0] && out.vendor[0] != '-' && (unsigned char)out.vendor[0] < 0x80)
        snprintf(out.device_class, sizeof(out.device_class), "%s device", out.vendor);
    else
        strncpy(out.device_class, "Unknown BLE", sizeof(out.device_class)-1);
}

static void ble_identify(BLEAdvertisedDevice& d, BleIdentity& out) {
    memset(&out, 0, sizeof out);
    out.company_id = 0xFFFF;
    out.rssi = d.getRSSI();

    {
        std::string a = d.getAddress().toString();
        strncpy(out.addr, a.c_str(), sizeof(out.addr)-1);
    }
    uint8_t at = d.getAddressType();
    if (at == 0 && out.addr[0]) {
        unsigned v = 0; sscanf(out.addr, "%2x", &v);
        if ((v & 0xC0) == 0xC0) at = 1;
        if ((v & 0xC0) == 0x40) at = 3;
    }
    strncpy(out.addr_type, addr_type_name(at), sizeof(out.addr_type)-1);
    out.is_random_mac = (at == 1 || at == 3);

    // Public MAC OUI
    if (at == 0 && !out.is_random_mac) {
        uint32_t oui = mac_to_oui(out.addr);
        const char* on = oui_name(oui);
        if (on) strncpy(out.vendor, on, sizeof(out.vendor)-1);
        if (oui == 0xB41E52) {
            strncpy(out.device_class, "Flock Safety camera", sizeof(out.device_class)-1);
            strncpy(out.kind, "Flock OUI", sizeof(out.kind)-1);
        }
        if (on && strstr(on, "Espressif"))
            strncpy(out.kind, "Espressif MAC", sizeof(out.kind)-1);
    }

    if (d.haveName()) {
        std::string nm = d.getName();
        strncpy(out.name, nm.c_str(), sizeof(out.name)-1);
    } else strncpy(out.name, "(no name)", sizeof(out.name)-1);

    // Manufacturer data
    const uint8_t* mfrp = nullptr; size_t mfrl = 0;
    if (d.haveManufacturerData()) {
        String md = d.getManufacturerData().c_str();
        mfrp = (const uint8_t*)md.c_str(); mfrl = md.length();
        if (mfrl >= 2) {
            uint16_t cid = (uint16_t)mfrp[0] | ((uint16_t)mfrp[1] << 8);
            out.company_id = cid;
            const char* cn = company_name(cid);
            if (cn) strncpy(out.vendor, cn, sizeof(out.vendor)-1);
            else if (!out.vendor[0]) snprintf(out.vendor, sizeof(out.vendor), "CID 0x%04X", cid);

            if (cid == 0x004C && mfrl >= 25 && mfrp[2] == 0x02 && mfrp[3] == 0x15) {
                out.is_ibeacon = true;
                strncpy(out.kind, "iBeacon", sizeof(out.kind)-1);
                uint16_t major = ((uint16_t)mfrp[20]<<8)|mfrp[21];
                uint16_t minor = ((uint16_t)mfrp[22]<<8)|mfrp[23];
                snprintf(out.detail, sizeof(out.detail), "maj %u min %u tx %d",
                         major, minor, (int)(int8_t)mfrp[24]);
            } else if (cid == 0x004C && mfrl >= 3) {
                uint8_t st = mfrp[2];
                const char* sn = "?";
                if (st==0x01) sn="Handoff"; else if (st==0x05) sn="AirDrop";
                else if (st==0x07) sn="AirPods"; else if (st==0x09) sn="AirPlay";
                else if (st==0x0C) sn="Handoff"; else if (st==0x10) sn="Nearby";
                else if (st==0x12) sn="FindMy";
                if (sn[0]!='?') snprintf(out.kind, sizeof(out.kind), "Apple %s", sn);
                else snprintf(out.kind, sizeof(out.kind), "Apple 0x%02X", st);
                snprintf(out.detail, sizeof(out.detail), "mfr %uB sub 0x%02X", (unsigned)mfrl, st);
            } else if (cid == 0x0006) {
                strncpy(out.kind, "Microsoft CDP", sizeof(out.kind)-1);
            } else {
                char hex[16]={0}; int n=(int)mfrl-2; if(n>6)n=6;
                for (int i=0;i<n;i++) sprintf(hex+i*2,"%02X", mfrp[2+i]);
                snprintf(out.detail, sizeof(out.detail), "mfr %uB %s", (unsigned)mfrl, hex);
            }
        }
    }

    if (d.haveAppearance() && !out.kind[0]) {
        const char* an = appearance_name(d.getAppearance());
        if (an) strncpy(out.kind, an, sizeof(out.kind)-1);
        else snprintf(out.kind, sizeof(out.kind), "App 0x%04X", d.getAppearance());
    }

    if (d.haveServiceUUID()) {
        std::string us = d.getServiceUUID().toString();
        uint16_t u16 = 0; unsigned v=0;
        if (us.size()>=4 && sscanf(us.c_str(), "%4x", &v)==1) u16=(uint16_t)v;
        if (!u16 && us.size()>=8 && sscanf(us.c_str()+4, "%4x", &v)==1) u16=(uint16_t)v;
        const char* sn = u16 ? service_name(u16) : nullptr;
        if (sn && !out.kind[0]) strncpy(out.kind, sn, sizeof(out.kind)-1);
        if (u16==0xFEAA) strncpy(out.kind, "Eddystone", sizeof(out.kind)-1);
        if (u16==0xFD6F) strncpy(out.kind, "Exposure Notif", sizeof(out.kind)-1);
        if (u16==0xFE2C) strncpy(out.kind, "Fast Pair", sizeof(out.kind)-1);
        if (u16==0xFD5A) strncpy(out.kind, "Samsung SmartTag svc", sizeof(out.kind)-1);
        if (!out.detail[0]) {
            if (sn) snprintf(out.detail, sizeof(out.detail), "svc %s", sn);
            else { char s[12]; size_t n=us.size()<8?us.size():8; memcpy(s,us.c_str(),n); s[n]=0;
                   snprintf(out.detail, sizeof(out.detail), "svc %s", s); }
        }
    }

    if (d.haveTXPower()) {
        char tmp[16]; snprintf(tmp, sizeof tmp, "tx %ddBm", (int)d.getTXPower());
        if (!out.detail[0]) strncpy(out.detail, tmp, sizeof(out.detail)-1);
        else { size_t n=strlen(out.detail); if (n+1+strlen(tmp)<sizeof(out.detail)) {
            out.detail[n]=' '; strcpy(out.detail+n+1, tmp); } }
    }

    // Full payload walk — all AD types the library may not surface individually
    if (d.getPayload() && d.getPayloadLength() > 0)
        parse_raw_ad(d.getPayload(), d.getPayloadLength(), out);

    if (d.haveServiceData() && !out.detail[0])
        snprintf(out.detail, sizeof(out.detail), "svcdata %uB", (unsigned)d.getServiceData().length());

    if (!out.vendor[0]) strncpy(out.vendor, "—", sizeof(out.vendor)-1);
    if (!out.kind[0])   strncpy(out.kind, "BLE device", sizeof(out.kind)-1);

    char prev[32]; strncpy(prev, out.device_class, sizeof(prev)-1);
    ble_classify(out, mfrp, mfrl);
    if (prev[0] && strstr(prev, "Flock") && !strstr(out.device_class, "Flock")) {
        if (strstr(out.device_class, "Unknown") || strstr(out.device_class, "device"))
            strncpy(out.device_class, prev, sizeof(out.device_class)-1);
    }
}
