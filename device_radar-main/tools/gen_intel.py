# Builds src/intel_db.h from registry prefix lists (IEEE data via maclookup.app / netify.ai / IPVM).
import re, sys
B = {}  # brand -> (cat, [prefixes])
def add(brand, cat, s):
    ps = [p.strip().upper() for p in re.split(r'[,\s]+', s) if p.strip()]
    B.setdefault(brand, (cat, []))[1].extend(ps)

# --- dedicated camera / doorbell / security makers (MED baseline) ---
add("Hikvision", "CAT_CAMERA", """E4:D5:8B, C8:A7:02, 08:54:11, 08:A1:89, 08:CC:81, 24:0F:9B, 24:32:AE, 24:48:45, 2C:A5:9C, 40:AC:BF, 44:19:B6, 44:A6:42, 4C:62:DF, 4C:BD:8F, 4C:F5:DC, 50:E5:38, 58:03:FB, 58:50:ED, 5C:34:5B, 64:DB:8B, 68:6D:BC, 80:F5:AE, 8C:E7:48, 94:E1:AC, 98:9D:E5, 98:DF:82, 98:F1:12, A0:FF:0C, A4:14:37, A4:D5:C2, AC:CB:51, B4:A3:82, BC:5E:33, BC:AD:28, BC:BA:C2, C0:51:7E, C0:56:E3, C0:6D:ED, DC:07:F8, 10:12:FB, E0:BA:AD, E0:CA:3C, E0:DF:13, EC:A9:71, A4:29:02, A4:A4:59, 80:48:9F, E8:A0:ED, FC:9F:FD, 04:03:12,
0C:75:D2, 18:68:CB, 18:80:25, 24:28:FD, 28:57:BE, 34:09:62, 3C:1B:F8, 44:47:CC, 54:8C:81, 54:C4:15, 74:3F:C2, 80:7C:62, 80:BE:AF, 84:9A:40, 98:8B:0A, AC:B9:2F, BC:9B:5E, C4:2F:90, D4:E8:53, DC:D2:6A, EC:C8:9C, F8:4D:FC, 4C:1F:86, A4:4B:D9, 88:DE:39, 84:94:59, 08:3B:C1, 00:BC:99, 04:EE:CD, 8C:22:D2, 48:78:5B, CC:13:F3, 40:B5:70, B0:FF:0D""")
add("Ezviz", "CAT_CAMERA", "94:EC:13, 20:BB:BC, 58:8F:CF, 64:F2:FB, 78:C1:AE, 34:C6:DD, EC:97:E0, 54:D6:0D, 78:A6:A0, 0C:A6:4C, AC:1C:26, 64:24:4D, F4:70:18, FC:24:22, 38:F2:5D")
add("Dahua", "CAT_CAMERA", "08:ED:ED, 14:A7:8B, 24:52:6A, 38:AF:29, 3C:E3:6B, 3C:EF:8C, 4C:11:BF, 5C:F5:1A, 64:FD:29, 6C:1C:71, 74:C9:29, 8C:E9:B4, 90:02:A9, 98:F9:CC, 9C:14:63, A0:BD:1D, B4:4C:3B, BC:32:5F, C0:39:5A, C4:AA:C4, D4:43:0E, E0:2E:FE, E0:50:8B, E4:24:6C, F4:B1:C2, FC:5F:49, FC:B6:9D")
add("Uniview", "CAT_CAMERA", "6C:F1:7E, 48:EA:63, C4:79:05, 88:26:3F, 14:BA:88")
add("Axis", "CAT_CAMERA", "00:40:8C, AC:CC:8E")
add("Avigilon", "CAT_CAMERA", "00:18:85")
add("Hanwha", "CAT_CAMERA", "00:09:18, E4:30:22")
add("FLIR", "CAT_CAMERA", "00:1B:D8, 00:40:7F")
add("Bosch Security", "CAT_CAMERA", "00:01:31, 00:04:63, 00:10:17, 00:1B:86, 00:1C:44, 00:07:5F")
add("Ring", "CAT_CAMERA", "AC:9F:C3, 18:7F:88, 34:3E:A4, 54:E0:19, 5C:47:5E, 64:9A:63, 90:48:6C, 9C:76:13, CC:3B:FB, C4:DB:AD, 24:2B:D6, 00:B4:63, 50:E4:67")
add("Wyze", "CAT_CAMERA", "2C:AA:8E, 7C:78:B2, 80:48:2C, D0:3F:27, F0:C8:8B")
add("Arlo", "CAT_CAMERA", "48:62:64, A4:11:62, FC:9C:98")
add("Blink", "CAT_CAMERA", "3C:A0:70, 70:AD:43, 74:13:48, 74:AB:93, C8:19:D8, F0:74:C1")
add("Nest", "CAT_CAMERA", "18:B4:30, 64:16:66")
add("Reolink", "CAT_CAMERA", "EC:71:DB")
add("Lorex", "CAT_CAMERA", "00:1F:54")
add("Swann", "CAT_CAMERA", "BC:51:FE")
add("SimpliSafe", "CAT_CAMERA", "F8:51:28")
add("Imilab (Xiaomi)", "CAT_CAMERA", "B4:10:1C, B8:88:80, 94:F8:27, 60:7E:A4, 78:DF:72")
add("Reecam", "CAT_CAMERA", "E8:AB:FA")
add("Focus Vision", "CAT_CAMERA", "68:DD:26")
# --- public-safety gear ---
add("Axon", "CAT_POLICE", "00:25:DF")
add("WatchGuard Video", "CAT_POLICE", "00:1D:96")
add("Motorola Solutions", "CAT_POLICE", "00:1F:92, 10:74:6F, 4C:CC:34, B8:E2:8C, 00:04:7D")
add("Flock Safety", "CAT_LPR", "B4:1E:52")
add("Cradlepoint", "CAT_VEHICLE", "00:E0:1C")
# --- drones ---
add("DJI", "CAT_DRONE", "04:A8:5A, 0C:9A:E6, 34:D2:62, 48:1C:B9, 58:B8:58, 60:60:1F, 8C:58:23, E4:7A:2C")
# --- attack hardware ---
add("Flipper Devices", "CAT_ATTACK", "0C:FA:22")
add("Pineapple-default MAC", "CAT_ATTACK", "00:13:37")
# --- radios inside cheap / DIY / Tapo cameras: soft warning, traffic decides ---
add("Espressif", "CAT_IOT", """DC:1E:D5, 08:3A:F2, 08:D1:F9, 08:B6:1F, 0C:8B:95, 24:DC:C3, 2C:F4:32, 30:C6:F7, 30:C9:22, 34:98:7A, 34:AB:95, 34:B4:72, 34:B7:DA, 3C:61:05, 3C:84:27, 3C:E9:0E, E8:6B:EA, 48:31:B7, 54:32:04, 54:5A:A6, 58:CF:79, 60:01:94, 70:04:1D, 78:21:84, 80:65:99, 80:7D:3A, 84:F7:03, 84:FC:E6, 8C:CE:4E, 94:E6:86, A0:76:4E, A4:CF:12, A8:42:E3, B0:B2:1C, B4:8A:0A, B4:E6:2D, B8:D6:1A, C4:4F:33, C0:4E:30, C4:DD:57, C4:DE:E2, CC:50:E3, D8:BF:C0, D8:BC:38, DC:54:75, 7C:73:98, E0:E2:E6, D0:EF:76, 48:CA:43, EC:C9:FF,
E4:B0:63, 24:EC:4A, C0:5D:89, 90:15:06, 34:5F:45, 88:13:BF, 7C:2C:67, D8:3B:DA, 98:3D:AE, B0:81:84, F0:9E:9E, D4:8C:49, A0:85:E3, F8:B3:B7, 8C:4F:00, E4:B3:23, E4:65:B8, 20:43:A8, 3C:8A:1F, F0:08:D1, F4:12:FA, FC:B4:67, 68:B6:B3, FC:F5:C4, 78:E3:6D, 40:22:D8, A0:A3:B3, 08:F9:E0, 24:4C:AB, 4C:11:AE, 0C:DC:7E, 10:06:1C, 10:52:1C, 1C:9D:C2, 24:D7:EB, 30:30:F9, 34:85:18, 40:4C:CA, 40:F5:20, 48:3F:DA, 4C:75:25, 5C:CF:7F, 84:CC:A8, 90:97:D5, 94:B5:55, 98:F4:AB, AC:0B:FB, B8:F0:09, C0:49:EF, C8:2B:96,
C8:2E:18, D4:8A:FC, E8:68:E7, E8:DB:84, 68:67:25, 7C:9E:BD, 7C:DF:A1, 84:0D:8E, 8C:AA:B5, 90:38:0C, A8:48:FA, CC:DB:A7, D8:F1:5B, DC:DA:0C, E0:98:06, E8:31:CD, EC:94:CB, EC:DA:3B, F0:F5:BD, FC:E8:C0, A0:DD:6C, 10:00:3B, 94:A9:90, B4:3A:45, FC:01:2C, 14:33:5C, 98:88:E0, 68:25:DD, 00:4B:12, 50:78:7D, 90:E5:B1, 98:A3:16, 78:1C:3C, B8:F8:62, 44:1D:64, A8:46:74, 28:56:2F, 80:F3:DA, 4C:C3:82, D0:CF:13, 88:57:21, 94:51:DC, 9C:13:9E, 20:6E:F1, 58:E6:C5, 48:F6:EE, 68:FE:71, DC:B4:D9, 00:70:07, 20:E7:C8,
80:F1:B2, C0:CD:D6, 08:92:72, 3C:DC:75, D4:E9:F4, E0:8C:FE, 88:56:A6, D8:85:AC, 90:70:69, A4:F0:0F, E8:F6:0A, 1C:C3:AB, AC:EB:E6, B0:A6:04, F4:2D:C9, 30:76:F5, AC:A7:04, E0:72:A1, 70:4B:CA, 04:B2:47, F8:5B:1B, A0:F2:62, B4:BF:E9, 14:C1:9F, 48:9D:31, E8:3D:C1, 20:9B:A9, 88:F1:55, AC:27:6E, 8C:94:DF, A4:CB:8F, 68:09:47, 70:AF:09, 8C:8C:29, 14:63:93, 1C:8F:57, 90:64:9B, 9C:CC:01, 44:B1:76, 68:EE:8F, C8:85:41, B8:7B:4D, D4:05:92, 7C:0C:5F, 7C:4F:AD, 7C:E8:B1, B0:3F:D3, B8:1F:3F, 34:94:54, DC:06:75,
5C:01:3B, F4:65:0B, 10:97:BD, 28:37:2F, 30:ED:A0, 10:91:A8, 08:3A:8D, 0C:B8:15, 18:FE:34, 24:0A:C4, 24:58:7C, 24:62:AB, 24:6F:28, 24:B2:DE, 2C:3A:E8, 30:83:98, 30:AE:A4, 34:86:5D, 3C:71:BF, 40:91:51, 44:17:93, 48:27:E2, 48:55:19, 48:E7:29, 4C:EB:D6, 50:02:91, 54:43:B2, 58:BF:25, 60:55:F9, 64:E8:33, 68:C6:3A, 6C:B4:56, E8:9F:6D, 70:B8:F6, 74:4D:BD, 7C:87:CE, 84:F3:EB, 58:8C:81, 8C:4B:14, 94:3C:C6, 94:B9:7E, 98:CD:AC, 9C:9C:1F, A0:20:A6, A0:B7:65, A4:7B:9D, A4:E5:7C, A8:03:2A, AC:67:B2, AC:D0:74,
B0:A7:32, BC:DD:C2, BC:FF:4D, C4:5B:BE, C8:C9:A3, C8:F0:9E, CC:8D:A2, CC:7B:5C, D4:D4:DA, D4:F9:8D, D8:13:2A, D8:A0:1D, DC:4F:22, E0:5A:1B, C4:D8:D5, 18:8B:0E, 2C:BC:BB, 08:A6:F7, AC:15:18, 9C:9E:6E, 1C:69:20, 34:CD:B0, 78:EE:4C, 94:54:C5, F0:24:F9, E8:06:90, 8C:BF:EA, 78:42:1C, CC:BA:97, EC:62:60, EC:64:C9, EC:FA:BC, F4:CF:A2, 70:03:9F, 24:A1:60, 64:B7:08, 80:64:6F, 14:2B:2F, 04:83:08, 38:18:2B, EC:E3:34, 08:AD:0A, 20:50:0D, 10:51:DB, 10:20:BA, 6C:C8:40, 0C:4E:A0, 80:B5:4E, 10:B4:1D, 84:1F:E8,
14:08:08, 1C:DB:D4, 28:05:A5, 3C:0F:02, B0:CB:D8, 38:44:BE, 8C:FD:49, 44:1B:F6, F0:16:1D, 28:84:85, 10:BD:A3, 58:2A:BD, 44:BD:8D, 80:45:6B, 90:DA:72, 38:3E:51, 68:9D:D2, 84:C7:BB, B4:A6:4A, 7C:D5:44, 98:C3:77, C8:8A:7B, DC:0A:69, 48:AF:F3, 90:B3:39, C4:9E:7E, CC:68:C7, 1C:29:04, 20:25:65, 80:53:E0, CC:7E:1F, 44:7B:30, 54:9D:EA, 64:89:14, DC:55:B1, 00:FB:4A, A8:FD:07, EC:D6:1B, F8:43:EE, 40:2B:D6, 58:2B:D3, 74:89:27, C8:ED:8B, 4C:84:21, 8C:45:98, BC:19:26, C8:EA:71, 1C:64:65, 3C:E2:55, A4:E9:72,
E8:ED:BD, 34:C9:34, 6C:2F:A0, CC:E7:32, F8:0C:4E, 20:D5:C2, 6C:3D:D8, B8:BB:11, C8:DA:29""")
add("TP-Link", "CAT_IOT", """00:0A:EB, 00:14:78, 00:19:E0, 00:1D:0F, 00:21:27, 00:23:CD, 00:25:86, 00:27:19, 8C:90:2D, D4:01:6D, 04:F9:F8, 08:1F:71, 08:57:00, 0C:4B:54, 0C:72:2C, 0C:80:63, 0C:82:68, 10:FE:ED, 14:75:90, 14:86:92, 14:CC:20, 14:CF:92, 14:D8:64, 14:E6:E4, 18:A6:F7, 18:D6:C7, 18:F2:2C, 1C:3B:F3, 1C:44:19, 1C:FA:68, 20:6B:E7, 20:DC:E6, 24:69:68, 28:2C:B2, 28:EE:52, 60:3A:7C, 30:B4:9E, 30:B5:C2, 30:FC:68, 34:96:72, 34:E8:94, 34:F7:16, 38:83:45, 3C:06:A7, 3C:46:D8, 3C:6A:48, 3C:84:6A, 40:16:9F, 40:3F:8C, 44:B3:2D,
48:0E:EC, 48:5F:08, 48:7D:2E, 50:3E:AA, 50:BD:5F, 50:C7:BF, 50:D4:F7, 50:FA:84, 54:75:95, 54:A7:03, 54:C8:0F, 54:E6:FC, 58:41:20, 5C:63:BF, 5C:89:9A, 60:29:2B, 60:32:B1, 60:E3:27, 64:56:01, 64:66:B3, 64:6E:97, 64:70:02, 68:77:24, 68:DD:B7, 68:FF:7B, 6C:B1:58, 6C:E8:73, 70:4F:57, 74:05:A5, 74:DA:88, 74:EA:3A, 78:44:FD, 78:60:5B, 78:A1:06, 7C:8B:CA, 7C:B5:9B, 80:89:17, 80:8F:1D, 80:EA:07, 84:16:F9, 84:D8:1B, 88:25:93, 8C:21:0A, 8C:A6:DF, 90:9A:4A, 90:AE:1B, 90:F6:52, 94:0C:6D, 94:D9:B3, 98:48:27,
98:97:CC, 98:DA:C4, 98:DE:D0, 9C:21:6A, 9C:A6:15, A0:F3:C1, A4:1A:3A, A4:2B:B0, A8:15:4D, A8:57:4E, AC:84:C6, B0:48:7A, B0:4E:26, B0:95:75, B0:95:8E, B0:BE:76, B8:F8:83, BC:46:99, BC:D1:77, C0:25:E9, C0:4A:00, C0:61:18, C0:C9:E3, C0:E4:2D, C4:6E:1F, C4:71:54, C4:E9:84, CC:08:FB, CC:32:E5, CC:34:29, D0:37:45, D0:76:E7, D0:C7:C0, D4:6E:0E, D8:07:B6, D8:0D:17, D8:15:0D, D8:47:32, D8:5D:4C, DC:00:77, DC:FE:18, E0:05:C5, 24:5A:5F, 4C:10:D5, 74:39:89, 80:AE:54, 30:68:93, E4:C3:2A, E4:D3:32, E8:94:F6,
E8:DE:27, EC:08:6B, EC:17:2F, EC:26:CA, EC:60:73, EC:88:8F, F0:F3:36, F4:2A:7D, F4:6D:2F, F4:83:CD, F4:84:8D, F4:EC:38, F4:F2:6D, F8:1A:67, F8:6F:B0, F8:8C:21, F8:D1:11, FC:D7:33, 98:BA:5F, 60:A3:E3, 9C:47:82, F8:C9:03, F8:CE:21, EC:75:0C, BC:07:1D, 3C:6A:D2, 00:31:92, 98:03:8E, A8:29:48, E0:D3:62, 04:C8:45, E0:28:0A, 0C:EF:15, 8C:86:DD, 48:22:54, 14:EB:B6, 20:36:26, 30:DE:4B, 40:ED:00, 50:91:E3, 54:AF:97, 5C:62:8B, 68:7F:F0, 6C:5A:B0, 78:8C:B5, 98:25:4A, AC:15:A2, B0:A7:B9, 7C:F1:7E, B0:19:21,
E4:FA:C4, 00:5F:67, 10:27:F5, 1C:61:B4, 24:2F:D0, 28:87:BA, 34:60:F9, 3C:52:A1, 5C:A6:E6, 5C:E9:31, 60:A4:B7, 74:FE:CE, 7C:C2:C6, 9C:53:22, 9C:A2:F4, A8:42:A1, B4:B0:24, C0:06:C3, CC:68:B6, 20:23:51, D8:44:89, F0:09:0D, 60:83:E7, A8:6E:84, DC:62:79, 3C:64:CF, E8:48:B8, F0:A7:31, 40:AE:30, 50:3D:D1, 78:20:51, 80:3C:04, B4:5B:D1, 04:0F:66, 48:C3:81, 5C:A6:4F, F4:F5:0B, 94:EF:50, D8:F1:2E, 40:95:95, CC:BA:BD, 10:5A:95, 3C:78:95, 58:04:4F, 6C:4C:BC, B8:FB:B3, 20:E1:5D, AC:A7:F1, 18:69:45, 58:D8:12,
2C:79:BE, 44:66:90, 84:B8:90, 88:99:86, B4:C0:C3, C0:3A:55, D4:D6:DF, EC:B9:31, 28:91:04, 60:15:6F, A8:29:DC, 90:1F:94, E4:43:CF, 54:D2:99, 78:C0:5A, 34:B1:26, BC:D8:49, D0:27:91, D0:5D:01""")

# MA-M (28-bit) blocks
MAM = [("A4:DA:22:2", "CAT_CAMERA", "Wyze"), ("0C:0E:C1:4", "CAT_CAMERA", "Swann")]

seen = {}
out = []
for brand, (cat, ps) in B.items():
    vals = []
    for p in ps:
        assert re.fullmatch(r'[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}', p), (brand, p)
        v = int(p.replace(':', ''), 16)
        if v in seen and seen[v] != brand:
            # collision: a later, more specific camera brand wins over generic chips
            print(f"note: {p} listed for {seen[v]} and {brand}", file=sys.stderr)
        if v in seen and seen[v] == brand:
            continue
        seen[v] = brand
        vals.append(v)
    out.append((brand, cat, sorted(vals)))

h = []
h.append('''/**
 * intel_db.h — threat-intel hardware prefixes for the Threat Audit.
 * GENERATED by gen_intel.py from IEEE registry data (via maclookup.app,
 * netify.ai and IPVM's camera list), November 2026. Built in at compile time.
 *
 * Categories decide the starting suspicion; traffic analysis then raises or
 * lowers it. Generic radios that sit inside cheap, DIY and Tapo cameras
 * (Espressif, TP-Link) are a deliberate soft warning, not a skip.
 * Extra entries can still be added on SD in /intel_oui.txt:  AABBCC,cam,Name
 */
#pragma once

enum IntelCat : uint8_t { CAT_NONE = 0, CAT_CAMERA, CAT_LPR, CAT_POLICE, CAT_DRONE, CAT_VEHICLE, CAT_ATTACK, CAT_IOT };
static const char* const CAT_NAME[] = {"", "camera maker", "plate reader", "public-safety gear", "drone",
                                       "vehicle router", "attack tool", "IoT radio (cam-capable)"};

struct IntelBrand { const char* name; uint8_t cat; const uint32_t* ouis; uint16_t n; };
''')
for brand, cat, vals in out:
    ident = 'kOui_' + re.sub(r'[^A-Za-z0-9]', '_', brand)
    rows = []
    for i in range(0, len(vals), 10):
        rows.append('    ' + ', '.join(f'0x{v:06X}' for v in vals[i:i+10]) + ',')
    h.append(f'static const uint32_t {ident}[] = {{  // {brand}: {len(vals)}\n' + '\n'.join(rows) + '\n};')
h.append('\nstatic const IntelBrand kIntelBrands[] = {')
for brand, cat, vals in out:
    ident = 'kOui_' + re.sub(r'[^A-Za-z0-9]', '_', brand)
    h.append(f'    {{"{brand}", {cat}, {ident}, (uint16_t)(sizeof {ident} / sizeof {ident}[0])}},')
h.append('};')
h.append('static constexpr int kIntelBrandCount = sizeof(kIntelBrands) / sizeof(kIntelBrands[0]);\n')
h.append('struct IntelMam { uint32_t prefix28; uint8_t cat; const char* name; };   // 28-bit (MA-M) blocks')
h.append('static const IntelMam kIntelMam[] = {')
for p, cat, name in MAM:
    v = int(p.replace(':', ''), 16)
    h.append(f'    {{0x{v:07X}, {cat}, "{name}"}},')
h.append('};\n')
total = sum(len(v) for _, _, v in out) + len(MAM)
h.append(f'// {total} prefixes across {len(out)} brands')
open(sys.argv[1], 'w').write('\n'.join(h) + '\n')
print(f"wrote {total} prefixes, {len(out)} brands")
