/**
 * audit_analysis.h — correlation engine for the Threat Audit.
 *
 *   · PLACES: the set of strongest access points is a location fingerprint.
 *     When it changes completely you've moved, with no GPS needed. Anything
 *     seen at two or more places is travelling with you.
 *   · CAMERA SCORE: maker prefix + sustained upload + steady always-on stream
 *     + upload/download ratio + proximity, minus phone-style random MACs.
 *   · FINDINGS: every rule below, ranked, de-duplicated, HIGH ones announced.
 *   · FRIENDLY list (your own phone, hotspot, tags) persists on SD.
 */
#pragma once

enum : uint8_t { SEV_INFO = 0, SEV_LOW, SEV_MED, SEV_HIGH };
static const char* const SEV_TAG[] = {"INFO", "LOW", "MED", "HIGH"};
enum : uint8_t { ENT_NONE = 0, ENT_AP, ENT_STA, ENT_TRK, ENT_PROBE };

struct AudFinding {
    uint8_t  sev;
    uint8_t  ent;
    int16_t  idx;
    uint32_t key;
    char     title[32];
    char     detail[112];
};
static constexpr int AUD_MAX_FIND = 48;
static AudFinding aud_find[AUD_MAX_FIND];
static int        aud_find_n = 0;
static int        aud_level = 1, aud_high_n = 0, aud_med_n = 0;

static uint32_t aud_alerted[64];
static int      aud_alerted_n = 0;
static uint32_t aud_banner_until = 0, aud_vib_until = 0, aud_build_t = 0, aud_start_t = 0;
static char     aud_banner[40] = "";

// ---------------------------------------------------------------------------
//  Friendly list (SD: /friendly.txt, one id per line)
// ---------------------------------------------------------------------------
static constexpr int AUD_MAX_FRIENDLY = 32;
static char aud_friendly[AUD_MAX_FRIENDLY][18];
static int  aud_friendly_n = 0;

static bool friendly_has(const char* id) {
    for (int i = 0; i < aud_friendly_n; ++i) if (!strcasecmp(aud_friendly[i], id)) return true;
    return false;
}
static bool friendly_mac(const uint8_t* m) { char b[18]; mac_str(m, b); return friendly_has(b); }

static void friendly_save() {
    SD.remove("/friendly.txt");
    File f = SD.open("/friendly.txt", FILE_WRITE);
    if (!f) return;
    for (int i = 0; i < aud_friendly_n; ++i) f.println(aud_friendly[i]);
    f.close();
}
static void friendly_load() {
    aud_friendly_n = 0;
    File f = SD.open("/friendly.txt", FILE_READ);
    if (!f) return;
    while (f.available() && aud_friendly_n < AUD_MAX_FRIENDLY) {
        String l = f.readStringUntil('\n');
        l.trim();
        if (l.length() >= 11) l.toCharArray(aud_friendly[aud_friendly_n++], 18);
    }
    f.close();
}
static bool friendly_toggle(const char* id) {
    for (int i = 0; i < aud_friendly_n; ++i)
        if (!strcasecmp(aud_friendly[i], id)) {
            for (int k = i; k < aud_friendly_n - 1; ++k) memcpy(aud_friendly[k], aud_friendly[k + 1], 18);
            aud_friendly_n--;
            friendly_save();
            return false;
        }
    if (aud_friendly_n < AUD_MAX_FRIENDLY) {
        strncpy(aud_friendly[aud_friendly_n], id, 17);
        aud_friendly[aud_friendly_n][17] = 0;
        aud_friendly_n++;
        friendly_save();
    }
    return true;
}

// ---------------------------------------------------------------------------
//  Places
// ---------------------------------------------------------------------------
static uint8_t  aud_place = 0, aud_places_n = 1;
static uint32_t aud_anchor[10];
static int      aud_anchor_n = 0;
static uint32_t aud_place_t = 0, aud_place_changed_t = 0;

static inline int places_count(uint16_t p) { return __builtin_popcount(p); }

static void aud_update_places() {
    uint32_t now = millis();
    // fingerprint = the 10 strongest fixed (non-random) access points heard lately
    static int top[AUD_MAX_AP];
    int cn = 0;
    for (int i = 0; i < aud_n; ++i) {
        AudAP& a = aud_ap[i];
        if (a.beaconed && now - a.seen <= 45000 && !mac_random(a.bssid)) top[cn++] = i;
    }
    std::sort(top, top + cn, [](int x, int y) { return aud_ap[x].rssi > aud_ap[y].rssi; });
    int n = std::min(cn, 10);
    if (n >= 3) {
        uint32_t set[10];
        for (int k = 0; k < n; ++k) set[k] = fnv1a_bytes(aud_ap[top[k]].bssid, 6);
        if (!aud_anchor_n) {
            memcpy(aud_anchor, set, n * sizeof(uint32_t));
            aud_anchor_n = n;
        } else {
            int inter = 0;
            for (int a = 0; a < n; ++a)
                for (int b = 0; b < aud_anchor_n; ++b) if (set[a] == aud_anchor[b]) { inter++; break; }
            float j = (float)inter / (float)(n + aud_anchor_n - inter);
            if (j < 0.2f) {
                aud_place = (uint8_t)((aud_place + 1) % 16);
                if (aud_places_n < 255) aud_places_n++;
                aud_place_changed_t = now;
                memcpy(aud_anchor, set, n * sizeof(uint32_t));
                aud_anchor_n = n;
                Serial.printf("PLACE %d (overlap %.2f)\n", aud_place, j);
            }
        }
    }
    uint16_t bit = (uint16_t)(1u << aud_place);
    for (int i = 0; i < aud_n; ++i) if (now - aud_ap[i].seen < 45000) aud_ap[i].places |= bit;
    for (int i = 0; i < AUD_MAX_STA; ++i) if (aud_sta[i].used && now - aud_sta[i].seen < 45000) aud_sta[i].places |= bit;
    for (int i = 0; i < aud_probe_n; ++i) if (now - aud_probe[i].seen < 45000) aud_probe[i].places |= bit;
    for (int i = 0; i < aud_trk_n; ++i) if (now - aud_trk[i].seen < 45000) aud_trk[i].places |= bit;
}

static bool is_following(uint16_t places, uint32_t first_seen, uint32_t seen) {
    uint32_t now = millis();
    return places_count(places) >= 2 && (places & (1u << aud_place)) &&
           now - first_seen >= 300000 && now - seen < 90000;
}

static const char* dur_str(uint32_t ms, char* b, size_t n) {
    uint32_t s = ms / 1000;
    if (s < 60) snprintf(b, n, "%lus", (unsigned long)s);
    else if (s < 3600) snprintf(b, n, "%lum", (unsigned long)(s / 60));
    else snprintf(b, n, "%luh%02lum", (unsigned long)(s / 3600), (unsigned long)((s / 60) % 60));
    return b;
}

// ---------------------------------------------------------------------------
//  People estimate
// ---------------------------------------------------------------------------
// Phones are the proxy for people.
//   · iPhones: Apple Continuity "Nearby Info" adverts (BLE), counted per
//     address inside a 60 s window. Apple rotates these addresses every ~15
//     min, so a short window doesn't double-count.
//   · Android / other phones: WiFi probe-request senders clustered into
//     devices by IE fingerprint + sequence-number continuity (randomisation-
//     aware counting, Vanhoef et al. 2016 / TrueSight / Espresso), excluding
//     probes that carry Apple's vendor element. Idle phones probe rarely, so
//     this side is a lower bound.
//   · people = phones / 0.91 (Pew 2025: 91% of US adults own a smartphone);
//     the iPhone-only cross-check divides by 0.58 (US iOS share, 2026).
// Reported as a range plus a coarse category, which BLE crowd research
// recommends over a single exact headcount.
static constexpr float P_SMARTPHONE = 0.91f, S_IOS_US = 0.58f;

struct CrowdEst {
    int   apple, apple_near, wifi, wifi_apple, wifi_other, wifi_other_near;
    float est, lo, hi;
    int   near_est;
    const char* cat;
};
static uint16_t aud_crowd_hist[20];
static int      aud_crowd_hist_n = 0;
static uint32_t aud_crowd_t = 0;

static void crowd_estimate(CrowdEst& c) {
    memset(&c, 0, sizeof c);
    uint32_t now = millis();
    for (int i = 0; i < AUD_MAX_APPLE; ++i)
        if (aud_apple_t[i] && now - aud_apple_t[i] < 60000 && aud_apple_r[i] >= -90) {
            c.apple++;
            if (aud_apple_r[i] >= -70) c.apple_near++;
        }
    for (int i = 0; i < aud_pdev_n; ++i) {
        ProbeDev& d = aud_pdev[i];
        if (now - d.t > 120000 || d.rssi < -90) continue;
        c.wifi++;
        if (d.apple) c.wifi_apple++;
        else { c.wifi_other++; if (d.rssi >= -70) c.wifi_other_near++; }
    }
    int phones = c.apple + c.wifi_other;
    float by_phones = phones / P_SMARTPHONE;
    float by_ios    = c.apple / (P_SMARTPHONE * S_IOS_US);
    // Direct phone count is the floor (idle Androids hide); the iPhone-share model
    // fills in the unseen Androids. Blend so neither assumption dominates.
    c.est = std::max(by_phones, 0.5f * (by_phones + by_ios));
    c.lo  = std::max<float>((float)std::max(c.apple, c.wifi) / 1.3f, phones / 1.3f);   // Watch + iPhone owners
    c.hi  = c.est * 1.25f + sqrtf(c.est) + 0.5f;
    c.near_est = (int)lroundf((c.apple_near + c.wifi_other_near) / P_SMARTPHONE);
    float e = c.est;
    c.cat = e < 1.5f ? "ALONE" : e < 6 ? "A FEW PEOPLE" : e < 16 ? "SMALL GROUP" : e < 50 ? "CROWD" : "LARGE CROWD";
}

// ---------------------------------------------------------------------------
//  Camera score (0–100) for any data transmitter
// ---------------------------------------------------------------------------
static void sta_vendor(AudSta& s) {
    if (s.vend_done) return;
    intel_vendor(s.mac, s.vendor, sizeof s.vendor, &s.cat);
    s.vend_done = true;
}

static uint8_t cam_score(AudSta& s, char* why = nullptr, size_t wn = 0) {
    sta_vendor(s);
    int sc = 0;
    char w[120] = "";
    auto note = [&](const char* t) { if (w[0]) strncat(w, ", ", sizeof w - strlen(w) - 1); strncat(w, t, sizeof w - strlen(w) - 1); };
    if (s.cat == CAT_CAMERA || s.cat == CAT_LPR) { sc += 45; note("camera maker"); }
    else if (s.cat == CAT_POLICE)                { sc += 40; note("public-safety maker"); }
    else if (s.cat == CAT_IOT)                   { sc += 15; note("cam-capable chip"); }
    bool traffic_counts = true;
    if (s.is_ap) {
        // an access point's downlink is normal router traffic, unless the AP itself looks like a camera
        int ai = aud_find_ap(s.mac);
        bool camap = ai >= 0 && (aud_ap[ai].cat == CAT_CAMERA || aud_ap[ai].cat == CAT_LPR ||
                                 strstr(aud_ap[ai].device_class, "amera") || ssid_cam_hint(aud_name(aud_ap[ai])));
        if (camap) { sc += 25; note("camera-style hotspot"); }
        else traffic_counts = false;
    }
    uint16_t med = sta_median_kbps(s);
    char t[40];
    if (traffic_counts && s.ring_n >= 3) {
        if (med >= 400)      { sc += 30; snprintf(t, sizeof t, "streams %u kbps", med); note(t); }
        else if (med >= 150) { sc += 20; snprintf(t, sizeof t, "streams %u kbps", med); note(t); }
        else if (med >= 60)  { sc += 8;  snprintf(t, sizeof t, "steady %u kbps", med); note(t); }
    }
    int active = 0;
    for (int i = 0; i < s.ring_n; ++i) if (s.ring[i] > 40) active++;
    if (traffic_counts && s.ring_n >= 6 && active * 4 >= s.ring_n * 3) { sc += 12; note("always transmitting"); }
    if (traffic_counts && s.tx_tot > 200000 && s.tx_tot > 4 * s.rx_tot) { sc += 10; note("mostly uploads"); }
    if (mac_random(s.mac)) { sc -= 30; note("random MAC (phone-like)"); }
    if (s.best >= -55) { sc += 8; note("very close"); }
    sc = constrain(sc, 0, 100);
    s.score = (uint8_t)sc;
    if (why && wn) { strncpy(why, w, wn - 1); why[wn - 1] = 0; }
    return (uint8_t)sc;
}

// ---------------------------------------------------------------------------
//  Findings
// ---------------------------------------------------------------------------
static void aud_add(uint8_t sev, uint32_t key, uint8_t ent, int idx, const char* title, const char* fmt, ...) {
    for (int k = 0; k < aud_find_n; ++k)                  // de-duplicate: keep the worse
        if (aud_find[k].key == key) {
            if (aud_find[k].sev >= sev) return;
            aud_find[k] = aud_find[--aud_find_n];
            break;
        }
    if (aud_find_n >= AUD_MAX_FIND) {
        int lo = 0;
        for (int k = 1; k < aud_find_n; ++k) if (aud_find[k].sev < aud_find[lo].sev) lo = k;
        if (aud_find[lo].sev >= sev) return;
        aud_find[lo] = aud_find[--aud_find_n];
    }
    AudFinding& f = aud_find[aud_find_n++];
    f.sev = sev; f.key = key; f.ent = ent; f.idx = (int16_t)idx;
    strncpy(f.title, title, sizeof f.title - 1); f.title[sizeof f.title - 1] = 0;
    va_list va; va_start(va, fmt);
    vsnprintf(f.detail, sizeof f.detail, fmt, va);
    va_end(va);
}

static int8_t ent_flag(uint8_t ent, int idx) {        // worst severity attached to an entity
    int8_t w = -1;
    for (int k = 0; k < aud_find_n; ++k)
        if (aud_find[k].ent == ent && aud_find[k].idx == idx && (int8_t)aud_find[k].sev > w) w = (int8_t)aud_find[k].sev;
    return w;
}

static bool name_is_bait(const char* s) {
    static const char* const bait[] = {"free", "guest", "public", "airport", "hotel", "starbucks",
                                       "xfinitywifi", "attwifi", "mcdonalds", "wifi"};
    for (auto b : bait) if (wifi_name_has(s, b)) return true;
    return false;
}
static bool name_is_default(const char* s) {
    static const char* const def[] = {"netgear", "linksys", "dlink", "d-link", "tp-link_", "tplink_",
                                      "tenda_", "belkin", "asus_", "default", "home-", "mywifi"};
    for (auto d : def) if (wifi_name_has(s, d)) return true;
    return false;
}
static const char* uptime_str(uint64_t tsf, char* b, size_t n) {
    uint32_t s = (uint32_t)(tsf / 1000000ULL);
    if (s < 3600) snprintf(b, n, "%lum", (unsigned long)(s / 60));
    else if (s < 86400) snprintf(b, n, "%luh", (unsigned long)(s / 3600));
    else snprintf(b, n, "%lud%luh", (unsigned long)(s / 86400), (unsigned long)((s / 3600) % 24));
    return b;
}

static void rid_describe(const RidInfo& r, char* out, size_t n) {
    int o = snprintf(out, n, "%s %s", r.id[0] ? r.id : "Unknown ID", UA_TYPE[r.ua_type & 15]);
    if ((r.have & 2) && o < (int)n)
        o += snprintf(out + o, n - o, ", %d m alt, %.1f m/s at %.5f,%.5f", r.alt_m, r.speed_dms / 10.0f, r.lat * 1e-7, r.lon * 1e-7);
    else if (o < (int)n) o += snprintf(out + o, n - o, ", position not yet received");
    if ((r.have & 4) && o < (int)n) snprintf(out + o, n - o, ". Pilot at %.5f,%.5f", r.op_lat * 1e-7, r.op_lon * 1e-7);
}

static void aud_build_findings() {
    aud_find_n = 0;
    uint32_t now = millis();
    char bs[18], d1[16];
    static const uint8_t pwn[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};

    // ===== RF environment =====
    int8_t floor_min = 0;
    for (int c = 1; c <= 13; ++c) if (ch_noise[c] < floor_min) floor_min = ch_noise[c];
    for (int c = 1; c <= 13; ++c) {
        if (ch_deauth_score[c] >= 6.0f) {
            int t = aud_find_ap(ch_deauth_target[c]);
            mac_str(ch_deauth_target[c], bs);
            aud_add(SEV_HIGH, 0xDE000000u | c, t >= 0 ? ENT_AP : ENT_NONE, t, "DEAUTH ATTACK",
                    "ch %d: ~%.0f kick frames/s%s at %s. Someone is knocking devices off WiFi.",
                    c, ch_deauth_rate[c], ch_deauth_bcast[c] ? " (broadcast, everyone)" : "",
                    t >= 0 ? aud_name(aud_ap[t]) : bs);
        }
        if (ch_noise[c] < 0 && floor_min < 0 && ch_noise[c] > -80 && ch_noise[c] - floor_min >= 12)
            aud_add(SEV_MED, 0x40150000u | c, ENT_NONE, -1, "RF INTERFERENCE",
                    "ch %d noise floor %d dBm vs %d elsewhere. Jammer, faulty transmitter or microwave.",
                    c, ch_noise[c], floor_min);
    }
    int fresh = 0, fresh_rand = 0;
    if (now - aud_start_t > 10000)
        for (int i = 0; i < aud_n; ++i)
            if (now - aud_ap[i].first_seen < 10000) { fresh++; if (mac_random(aud_ap[i].bssid)) fresh_rand++; }
    if (fresh_rand >= 20 || fresh >= 40)
        aud_add(SEV_HIGH, fnv1a("beaconflood"), ENT_NONE, -1, "BEACON FLOOD",
                "%d networks appeared in 10 s (%d with fake MACs). A spam tool is running nearby.", fresh, fresh_rand);
    if (aud_spam_n && now - aud_spam_t < 15000)
        aud_add(SEV_HIGH, fnv1a("blespam"), ENT_NONE, -1, "BLE SPAM ATTACK",
                "%d fake Apple pop-up adverts in 2 s. A Flipper-style spam tool is running nearby.", aud_spam_n);

    // ===== access points =====
    for (int i = 0; i < aud_n; ++i) {
        AudAP& a = aud_ap[i];
        if (now - a.seen > 120000) continue;
        mac_str(a.bssid, bs);
        if (friendly_has(bs)) continue;
        uint32_t k = fnv1a_bytes(a.bssid, 6);
        const char* nm = aud_name(a);

        if (a.tsf_jumps && now - a.tsf_jump_t > 120000) a.tsf_jumps = 0;
        if (a.tsf_jumps >= 4)
            aud_add(SEV_HIGH, k ^ 0x10, ENT_AP, i, "CLONED BSSID",
                    "Two radios are using %s (\"%s\"): its beacon clock keeps jumping. Classic evil-twin trick.", bs, nm);
        if (a.spoof_deauth >= 2)
            aud_add(SEV_HIGH, k ^ 0x11, ENT_AP, i, "SPOOFED DEAUTH",
                    "%d forged kick frames claiming to be \"%s\": sequence numbers don't match the real AP.",
                    a.spoof_deauth, nm);
        if (a.cat == CAT_ATTACK || wifi_name_has(a.ssid, "pineapple"))
            aud_add(SEV_HIGH, k ^ 0x12, ENT_AP, i, "ATTACK HARDWARE",
                    "%s broadcasting \"%s\". Rogue-AP / man-in-the-middle kit.", a.vendor, nm);
        if (!memcmp(a.bssid, pwn, 6))
            aud_add(SEV_HIGH, k ^ 0x13, ENT_AP, i, "PWNAGOTCHI",
                    "Handshake-harvesting bot nearby. It collects WiFi password hashes to crack offline.");
        if (a.names_n >= 3)
            aud_add(SEV_HIGH, k ^ 0x14, ENT_AP, i, "KARMA ROGUE AP",
                    "One radio (%s) is answering as %d different networks to lure phones in.", bs, (int)a.names_n);
        if (a.flags & APF_RID) {
            char rd[112];
            rid_describe(a.rid, rd, sizeof rd);
            aud_add(SEV_HIGH, a.rid.id[0] ? fnv1a(a.rid.id) : (k ^ 0x15), ENT_AP, i, "DRONE OVERHEAD", "%s", rd);
        } else if (a.cat == CAT_DRONE)
            aud_add(SEV_MED, k ^ 0x15, ENT_AP, i, "DRONE LINK",
                    "%s drone or controller network \"%s\" at %d dBm.", a.vendor, nm, a.best);
        if (a.cat == CAT_LPR || a.cat == CAT_POLICE)
            aud_add(SEV_MED, k ^ 0x16, ENT_AP, i, a.cat == CAT_LPR ? "PLATE READER" : "PUBLIC-SAFETY GEAR",
                    "%s network \"%s\", ch %d, %d dBm.", a.vendor, nm, a.ch, a.best);
        if (a.cat == CAT_VEHICLE)
            aud_add(SEV_LOW, k ^ 0x17, ENT_AP, i, "VEHICLE ROUTER",
                    "%s in-vehicle router (police, EMS and fleet use these): \"%s\", %d dBm.", a.vendor, nm, a.best);
        if (a.cat == CAT_CAMERA || strstr(a.device_class, "amera") || ssid_cam_hint(nm))
            aud_add(a.cat == CAT_CAMERA ? SEV_MED : SEV_LOW, k ^ 0xCA, ENT_AP, i, "CAMERA HOTSPOT",
                    "\"%s\" (%s): %s. Camera, doorbell or spy-cam access point.", nm, a.vendor,
                    a.cat == CAT_CAMERA ? "camera maker" : "camera-style name/class");
        if (is_following(a.places, a.first_seen, a.seen))
            aud_add(SEV_HIGH, k ^ 0x18, ENT_AP, i, "NETWORK FOLLOWING YOU",
                    "\"%s\" (%s) has been at %d of your places over %s. A hotspot is travelling with you.",
                    nm, a.vendor, places_count(a.places), dur_str(now - a.first_seen, d1, sizeof d1));
        bool young = a.tsf && a.tsf < 600ULL * 1000000ULL;
        if (young && a.best > -55 && a.first_seen - aud_start_t > 30000)
            aud_add(SEV_LOW, k ^ 0x19, ENT_AP, i, "NEW AP NEARBY",
                    "\"%s\" powered on %s ago, close to you (%d dBm).", nm, uptime_str(a.tsf, d1, sizeof d1), a.best);

        // evil twin / impersonation
        for (int j = 0; a.ssid[0] && a.beaconed && j < aud_n; ++j) {
            if (j == i) continue;
            AudAP& b = aud_ap[j];
            if (!b.beaconed || now - b.seen > 120000 || strcmp(a.ssid, b.ssid)) continue;
            if (a.sec == SEC_OPEN && b.sec != SEC_OPEN) {
                aud_add(SEV_HIGH, k ^ 0x20, ENT_AP, i, "EVIL TWIN",
                        "Open copy of encrypted network \"%s\" (%s, ch %d). Do not join.", a.ssid, bs, a.ch);
                break;
            }
            bool a_young = a.tsf && a.tsf < 600ULL * 1000000ULL, b_old = b.tsf > 3600ULL * 1000000ULL;
            if (a_young && b_old && a.ie_fp != b.ie_fp) {
                aud_add(SEV_HIGH, k ^ 0x20, ENT_AP, i, "IMPERSONATOR AP",
                        "\"%s\" copy switched on %s ago with a different radio stack than the original.",
                        a.ssid, uptime_str(a.tsf, d1, sizeof d1));
                break;
            }
            if (a.sec != SEC_OPEN && b.sec != SEC_OPEN && a.sec < b.sec && a.sec != SEC_WPA2E) {
                aud_add(SEV_MED, k ^ 0x20, ENT_AP, i, "SECURITY DOWNGRADE",
                        "\"%s\" seen as %s here but %s elsewhere. Possible twin forcing weaker crypto.",
                        a.ssid, SEC_NAME[a.sec], SEC_NAME[b.sec]);
                break;
            }
            bool av = strncmp(a.vendor, "OUI", 3) && strcmp(a.vendor, "randomized");
            bool bv = strncmp(b.vendor, "OUI", 3) && strcmp(b.vendor, "randomized");
            if (av && bv && strcmp(a.vendor, b.vendor) && a.ie_fp != b.ie_fp && a.best > b.best) {
                aud_add(SEV_LOW, k ^ 0x20, ENT_AP, i, "POSSIBLE TWIN",
                        "\"%s\" from %s and %s hardware with different radio stacks. Fine if one is an extender.",
                        a.ssid, a.vendor, b.vendor);
                break;
            }
        }

        // configuration weaknesses (skipped when something worse is already reported)
        if (ent_flag(ENT_AP, i) >= SEV_HIGH) continue;
        if (a.sec == SEC_WEP)
            aud_add(SEV_MED, k ^ 0x30, ENT_AP, i, "BROKEN CRYPTO", "\"%s\" uses WEP. Cracked in minutes; treat as open.", nm);
        else if (a.sec == SEC_OPEN && a.beaconed)
            aud_add(SEV_LOW, k ^ 0x30, ENT_AP, i, "OPEN NETWORK",
                    name_is_bait(nm) ? "\"%s\" is open with a common bait name. Trivial to impersonate."
                                     : "\"%s\" is open. Anyone nearby can read its traffic.", nm);
        if ((a.flags & APF_WPS) && !(a.flags & APF_WPS_LOCKED))
            aud_add(SEV_LOW, k ^ 0x31, ENT_AP, i, "WPS ATTACKABLE",
                    "\"%s\" has WPS on and unlocked: PIN brute-force / Pixie Dust risk.", nm);
        if (a.flags & APF_TKIP)
            aud_add(SEV_LOW, k ^ 0x32, ENT_AP, i, "TKIP ENABLED", "\"%s\" still allows TKIP, a broken cipher.", nm);
        if (name_is_default(nm))
            aud_add(SEV_LOW, k ^ 0x34, ENT_AP, i, "DEFAULT NAME", "\"%s\" looks factory-default: default admin password likely.", nm);
        if (a.hidden && a.revealed[0])
            aud_add(SEV_INFO, k ^ 0x35, ENT_AP, i, "DECLOAKED",
                    "Hidden network's real name is \"%s\" (leaked in a probe response).", a.revealed);
        else if (a.hidden && a.best > -55)
            aud_add(SEV_LOW, k ^ 0x35, ENT_AP, i, "HIDDEN AP CLOSE", "Hidden network %s very close (%d dBm), ch %d.", bs, a.best, a.ch);
    }

    // ===== data transmitters: cameras, followers =====
    for (int i = 0; i < AUD_MAX_STA; ++i) {
        AudSta& s = aud_sta[i];
        if (!s.used || now - s.seen > 180000) continue;
        if (friendly_mac(s.mac)) continue;
        mac_str(s.mac, bs);
        uint32_t k = fnv1a_bytes(s.mac, 6);
        uint8_t sc = cam_score(s);
        uint16_t med = sta_median_kbps(s);
        if (sc >= 70)
            aud_add(SEV_HIGH, k ^ 0xCA, ENT_STA, i, "CAMERA LIKELY",
                    "%s (%s) score %d: streams ~%u kbps, %d dBm. Run CHALLENGE to confirm it sees you.",
                    bs, s.vendor, sc, med, s.best);
        else if (sc >= 45)
            aud_add(SEV_MED, k ^ 0xCA, ENT_STA, i, "CAMERA CANDIDATE",
                    "%s (%s) score %d, ~%u kbps, %d dBm.", bs, s.vendor, sc, med, s.best);
        else if (s.cat == CAT_CAMERA || s.cat == CAT_LPR || s.cat == CAT_POLICE)
            aud_add(SEV_MED, k ^ 0xCA, ENT_STA, i, s.cat == CAT_POLICE ? "PUBLIC-SAFETY GEAR" : "CAMERA HARDWARE",
                    "%s device %s on the air (%d dBm). Idle now; may stream on motion.", s.vendor, bs, s.best);
        else if (s.cat == CAT_IOT && !s.is_ap && (sc >= 25 || s.best > -65))
            aud_add(SEV_LOW, k ^ 0xCA, ENT_STA, i, "CAM-CAPABLE IoT",
                    "%s radio %s at %d dBm, ~%u kbps. Could be a Tapo/ESP32 camera.", s.vendor, bs, s.best, med);
        if (is_following(s.places, s.first_seen, s.seen))
            aud_add(SEV_HIGH, k ^ 0x18, ENT_STA, i, "DEVICE FOLLOWING YOU",
                    "%s (%s) has been at %d of your places over %s.", bs, s.vendor,
                    places_count(s.places), dur_str(now - s.first_seen, d1, sizeof d1));
    }

    // ===== probe requests: what nearby phones leak =====
    int nearest = -1;
    for (int i = 0; i < aud_probe_n; ++i) {
        AudProbe& p = aud_probe[i];
        if (now - p.seen > 120000) continue;
        if (nearest < 0 || p.best > aud_probe[nearest].best) nearest = i;
        if (!mac_random(p.mac) && is_following(p.places, p.first_seen, p.seen) && !friendly_mac(p.mac)) {
            mac_str(p.mac, bs);
            aud_add(SEV_HIGH, fnv1a_bytes(p.mac, 6) ^ 0x18, ENT_PROBE, i, "PHONE FOLLOWING YOU",
                    "%s has been at %d of your places over %s.", bs, places_count(p.places),
                    dur_str(now - p.first_seen, d1, sizeof d1));
        }
    }
    if (nearest >= 0 && aud_probe[nearest].best > -45 && aud_probe[nearest].n) {
        AudProbe& p = aud_probe[nearest];
        char list[80] = "";
        for (int k = 0; k < p.n; ++k) {
            if (k) strncat(list, ", ", sizeof list - strlen(list) - 1);
            strncat(list, p.ssids[k], sizeof list - strlen(list) - 1);
        }
        aud_add(SEV_LOW, fnv1a("myleak"), ENT_PROBE, nearest, "YOUR PHONE LEAKS",
                "Nearest phone is broadcasting %d saved network names: %s", p.n, list);
    }

    // ===== BLE =====
    for (int i = 0; i < aud_trk_n; ++i) {
        AudTrk& t = aud_trk[i];
        if (now - t.seen > 120000 || friendly_has(t.addr)) continue;
        uint32_t k = fnv1a(t.addr);
        uint32_t age = now - t.first_seen;
        bool follow = is_following(t.places, t.first_seen, t.seen);
        if (t.kind == BK_RID) {
            char rd[112];
            rid_describe(t.rid, rd, sizeof rd);
            aud_add(SEV_HIGH, t.rid.id[0] ? fnv1a(t.rid.id) : (k ^ 0x15), ENT_TRK, i, "DRONE OVERHEAD", "%s", rd);
            continue;
        }
        if (bk_is_tracker(t.kind)) {
            bool lost = (t.kind == BK_FINDMY_SEP || t.kind == BK_FMDN_UTP);
            if (follow)
                aud_add(SEV_HIGH, k ^ 0x18, ENT_TRK, i, "TRACKER FOLLOWING YOU",
                        "%s has been at %d of your places over %s. Hunt it down: A in INTEL.",
                        BK_NAME[t.kind], places_count(t.places), dur_str(age, d1, sizeof d1));
            else if (lost && age >= 600000)
                aud_add(SEV_MED, k ^ 0x18, ENT_TRK, i, "LOST TRACKER WITH YOU",
                        "%s separated from its owner, near you for %s (%d dBm).", BK_NAME[t.kind], dur_str(age, d1, sizeof d1), t.best);
            else if (lost)
                aud_add(SEV_LOW, k ^ 0x18, ENT_TRK, i, "LOST TRACKER NEARBY",
                        "%s separated from its owner, %d dBm. Watching for it to follow.", BK_NAME[t.kind], t.best);
            else if (age >= 900000)
                aud_add(SEV_LOW, k ^ 0x18, ENT_TRK, i, "TRACKER NEARBY",
                        "%s near you for %s (%d dBm).", BK_NAME[t.kind], dur_str(age, d1, sizeof d1), t.best);
            continue;
        }
        if (t.kind == BK_GLASSES) {
            bool close = t.best > -65;
            aud_add(close ? SEV_HIGH : SEV_MED, k, ENT_TRK, i, close ? "CAMERA GLASSES CLOSE" : "CAMERA GLASSES",
                    "Meta/Ray-Ban or Snap glasses ID at %d dBm. Could be recording. (VR headsets share these IDs.)", t.best);
            continue;
        }
        if (t.kind == BK_TESLA) {
            if (follow)
                aud_add(SEV_HIGH, k ^ 0x18, ENT_TRK, i, "VEHICLE FOLLOWING YOU",
                        "The same Tesla (VIN-derived ID %s) has been at %d of your places over %s.",
                        t.name[0] ? t.name : t.addr, places_count(t.places), dur_str(age, d1, sizeof d1));
            else
                aud_add(SEV_LOW, k, ENT_TRK, i, "TESLA (SENTRY CAMS)",
                        "Tesla at %d dBm. In Sentry Mode its 8 cameras record everything around it.", t.best);
            continue;
        }
        if (t.kind == BK_FLIPPER)
            aud_add(SEV_MED, k, ENT_TRK, i, "FLIPPER ZERO", "\"%s\" nearby at %d dBm. Multi-tool for RFID, IR, sub-GHz and BLE attacks.",
                    t.name[0] ? t.name : t.addr, t.best);
        else if (t.kind == BK_POLICE)
            aud_add(follow ? SEV_HIGH : SEV_MED, k, ENT_TRK, i, follow ? "POLICE GEAR FOLLOWING" : "POLICE / LPR GEAR",
                    "%s (%s) at %d dBm.", t.cls[0] ? t.cls : "Public-safety device", t.name[0] ? t.name : t.addr, t.best);
        else if (t.kind == BK_CAMERA)
            aud_add(SEV_LOW, k, ENT_TRK, i, "CAMERA (BLE)", "%s (%s) at %d dBm.", t.cls, t.name[0] ? t.name : t.addr, t.best);
    }

    // rank: severity, then signal strength
    auto strength = [](const AudFinding& f) -> int {
        switch (f.ent) {
            case ENT_AP:    return f.idx >= 0 ? aud_ap[f.idx].best : -127;
            case ENT_STA:   return f.idx >= 0 ? aud_sta[f.idx].best : -127;
            case ENT_TRK:   return f.idx >= 0 ? aud_trk[f.idx].best : -127;
            case ENT_PROBE: return f.idx >= 0 ? aud_probe[f.idx].best : -127;
        }
        return 0;
    };
    std::sort(aud_find, aud_find + aud_find_n, [&](const AudFinding& x, const AudFinding& y) {
        if (x.sev != y.sev) return x.sev > y.sev;
        return strength(x) > strength(y);
    });

    aud_high_n = aud_med_n = 0;
    int lows = 0;
    for (int i = 0; i < aud_find_n; ++i) {
        if (aud_find[i].sev == SEV_HIGH) aud_high_n++;
        else if (aud_find[i].sev == SEV_MED) aud_med_n++;
        else if (aud_find[i].sev == SEV_LOW) lows++;
    }
    aud_level = aud_high_n >= 2 ? 5 : aud_high_n ? 4 : aud_med_n ? 3 : lows ? 2 : 1;

    for (int i = 0; i < aud_find_n; ++i) {
        if (aud_find[i].sev != SEV_HIGH) continue;
        bool seen = false;
        for (int k = 0; k < aud_alerted_n; ++k) if (aud_alerted[k] == aud_find[i].key) { seen = true; break; }
        if (seen) continue;
        if (aud_alerted_n < 64) aud_alerted[aud_alerted_n++] = aud_find[i].key;
        snprintf(aud_banner, sizeof aud_banner, "!! %s", aud_find[i].title);
        aud_banner_until = now + 2500;
        M5.Power.setVibration(200);
        aud_vib_until = now + 350;
        Serial.printf("ALERT: %s - %s\n", aud_find[i].title, aud_find[i].detail);
    }
}

// ---------------------------------------------------------------------------
//  Radio schedule
// ---------------------------------------------------------------------------
// One radio, two protocols. Espressif's arbiter can time-slice WiFi sniffing
// and BLE scanning on its own, but it rates that pairing "sniffer packet loss
// unstable", which would corrupt traffic rates, deauth counts and CHALLENGE.
// So the audit owns the schedule: two clean WiFi sweeps of all 13 channels,
// then one 2 s passive BLE window, repeat. Each side's results are cached in
// its tables between windows. Hunts and challenges hold the radio on one side.
enum : uint8_t { HOLD_NONE = 0, HOLD_WIFI, HOLD_BLE };
static uint8_t  aud_hold = HOLD_NONE;
static bool     aud_in_ble = false;
static uint32_t aud_sched_t = 0, aud_ble_win_t = 0;
static int      aud_sweeps = 0;
static constexpr int      SCHED_SWEEPS_PER_BLE = 2;
static constexpr uint32_t SCHED_BLE_TIMEOUT    = 3500;

static void sched_enter_ble() {
    aud_close_dwell(aud_cur_ch, millis() - aud_hop_t);
    esp_wifi_set_promiscuous(false);                 // WiFi silent: BLE gets the radio
    aud_in_ble = true;
    aud_ble_win_t = millis();
    aud_ble_window = true;
}
static void sched_leave_ble() {
    aud_in_ble = false;
    aud_ble_window = false;
    esp_wifi_set_promiscuous(true);
    aud_set_channel(aud_lock_ch > 0 ? aud_lock_ch : 1);
    aud_sweeps = 0;
}
static void aud_set_hold(uint8_t h) {
    aud_hold = h;
    if (h == HOLD_BLE) {                             // BLE-only (BLE fox hunt)
        if (!aud_in_ble) sched_enter_ble();
        aud_ble_continuous = true;
    } else {
        aud_ble_continuous = false;
        if (aud_in_ble) sched_leave_ble();
    }
}

static void aud_schedule(uint32_t now) {
    if (aud_in_ble) {
        bool done = !aud_ble_window || now - aud_ble_win_t > SCHED_BLE_TIMEOUT;
        if (aud_hold != HOLD_BLE && done) sched_leave_ble();
        return;
    }
    if (aud_lock_ch > 0) {                           // locked channel: fold stats once a second
        if (aud_cur_ch != aud_lock_ch) aud_set_channel(aud_lock_ch);
        if (now - aud_hop_t >= 1000) { aud_close_dwell(aud_cur_ch, now - aud_hop_t); aud_hop_t = now; }
        return;
    }
    if (now - aud_hop_t >= AUD_DWELL_MS) {
        aud_close_dwell(aud_cur_ch, now - aud_hop_t);
        if (aud_cur_ch == 13) {
            aud_sweeps++;
            if (aud_ble_ok && aud_hold == HOLD_NONE && aud_sweeps >= SCHED_SWEEPS_PER_BLE) { sched_enter_ble(); return; }
        }
        aud_set_channel(aud_cur_ch % 13 + 1);
    }
}

// Keep the radios scheduled and the picture current; call from every audit screen.
static bool aud_hunt_only = false;                  // radar-launched fox hunt: radio + drains only
static void aud_tick() {
    uint32_t now = millis();
    aud_schedule(now);
    aud_wifi_drain();
    aud_ble_drain();
    if (aud_hunt_only) return;
    if (now - aud_place_t >= 30000) { aud_place_t = now; aud_update_places(); }
    if (now - aud_crowd_t >= 30000) {
        aud_crowd_t = now;
        CrowdEst c; crowd_estimate(c);
        if (aud_crowd_hist_n == 20) { memmove(aud_crowd_hist, aud_crowd_hist + 1, 19 * sizeof(uint16_t)); aud_crowd_hist_n = 19; }
        aud_crowd_hist[aud_crowd_hist_n++] = (uint16_t)lroundf(c.est);
    }
    if (now - aud_build_t >= 1000) { aud_build_t = now; aud_build_findings(); }
    if (aud_vib_until && now > aud_vib_until) { M5.Power.setVibration(0); aud_vib_until = 0; }
}

static void aud_reset() {
    bool was = aud_on;
    aud_on = false;
    delay(10);
    aud_n = 0; aud_probe_n = 0; aud_trk_n = 0; aud_pdev_n = 0;
    for (int i = 0; i < AUD_MAX_APPLE; ++i) { aud_apple_h[i] = 0; aud_apple_t[i] = 0; }
    aud_crowd_hist_n = 0;
    if (aud_ap)    memset(aud_ap, 0, sizeof(AudAP) * AUD_MAX_AP);
    if (aud_sta)   memset(aud_sta, 0, sizeof(AudSta) * AUD_MAX_STA);
    if (aud_probe) memset(aud_probe, 0, sizeof(AudProbe) * AUD_MAX_PROBE);
    if (aud_trk)   memset(aud_trk, 0, sizeof(AudTrk) * AUD_MAX_TRK);
    for (int c = 0; c < 14; ++c) {
        aud_deauth_cnt[c] = 0; aud_frame_cnt[c] = 0; aud_noise_raw[c] = 0; aud_deauth_bcast[c] = 0;
        ch_deauth_score[c] = 0; ch_deauth_rate[c] = 0; ch_activity[c] = 0; ch_noise[c] = 0;
        ch_deauth_bcast[c] = false;
        memset(ch_deauth_target[c], 0, 6);
    }
    aud_deauth_total = 0;
    aud_find_n = 0; aud_level = 1; aud_high_n = aud_med_n = 0;
    aud_alerted_n = 0; aud_banner_until = 0;
    aud_spam_n = 0;
    aud_place = 0; aud_places_n = 1; aud_anchor_n = 0;
    aud_start_t = aud_place_t = aud_build_t = millis();
    if (aud_q) xQueueReset(aud_q);
    if (aud_bq) xQueueReset(aud_bq);
    aud_on = was;
}
