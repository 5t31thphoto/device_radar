/**
 * audit_ui.h — screens for the Threat Audit.
 *
 * Views (BtnB cycles): SITREP · CAMERAS · TRACKERS · LEAKS · SPECTRUM · NETWORKS
 * INTEL (tap any row):  A = FOX HUNT · B = CHALLENGE (cameras) · hold B = friendly
 *                       hold A = classic radar (access points) · C / tap = back
 * FOX HUNT: locks onto one transmitter until you find it.
 * CHALLENGE: proves a camera can see you by correlating its upload with motion.
 */
#pragma once

static constexpr uint16_t COL_BLACK   = 0x0000;
static constexpr uint16_t COL_AMBER   = 0xFD20;
static constexpr uint16_t COL_YELLOW  = 0xFFE0;
static constexpr uint16_t COL_WHITE   = 0xFFFF;
static constexpr uint16_t COL_MAGENTA = 0xC81F;

static uint16_t sev_col(uint8_t s) {
    switch (s) { case SEV_HIGH: return COL_RED; case SEV_MED: return COL_AMBER; case SEV_LOW: return COL_YELLOW; default: return COL_TEAL; }
}
static uint16_t sec_col(uint8_t s) {
    switch (s) { case SEC_OPEN: return COL_RED; case SEC_WEP: return COL_AMBER; case SEC_WPA: return COL_YELLOW;
                 case SEC_WPA3: case SEC_WPA23: return COL_LIME; default: return COL_TEAL; }
}
static uint16_t score_col(int sc) { return sc >= 70 ? COL_RED : sc >= 45 ? COL_AMBER : sc >= 25 ? COL_YELLOW : COL_TEAL; }

enum : uint8_t { V_SITREP = 0, V_CAMS, V_TRACK, V_CROWD, V_SENSE, V_LEAKS, V_SPECTRUM, V_NETS, V_COUNT };
static const char* const VIEW_TITLE[] = {"SITREP // EYES ONLY", "CAMERAS // WATCHERS", "TRACKERS // TAILS",
                                         "CROWD // WHO'S AROUND", "SENSE // AMBIENT MOTION", "LEAKS // WHAT PHONES SAY",
                                         "SPECTRUM // 2.4 GHz", "NETWORKS // DOSSIER"};
static const char* const LEVEL_NAME[] = {"", "CLEAR", "GUARDED", "ELEVATED", "HIGH", "SEVERE"};
static const uint16_t    LEVEL_COL[]  = {0, 0x07E0, COL_LIME, COL_YELLOW, COL_AMBER, COL_RED};

// ---------------------------------------------------------------------------
//  Shared drawing
// ---------------------------------------------------------------------------
static int draw_wrap(const char* s, int x, int y, int maxw, int line_h, int max_lines) {
    int lines = 0;
    const char* p = s;
    char buf[120];
    while (*p && lines < max_lines) {
        int bl = 0, last_space = -1;
        const char* q = p;
        while (*q && bl < 118) {
            buf[bl] = *q; buf[bl + 1] = 0;
            if (canvas->textWidth(buf) > maxw) break;
            if (*q == ' ') last_space = bl;
            ++bl; ++q;
        }
        if (*q && last_space > 0) { bl = last_space; q = p + last_space + 1; }
        buf[bl] = 0;
        canvas->drawString(buf, x, y + lines * line_h);
        ++lines;
        p = q;
        while (*p == ' ') ++p;
    }
    return lines;
}

static void aud_header(const char* title, int view = -1) {
    canvas->fillRect(0, 0, SCREEN_W, 22, COL_BLACK);
    canvas->setTextSize(1);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    canvas->setTextColor(COL_RED);
    draw_fit(title, 6, 3, 198);
    if (view >= 0)
        for (int v = 0; v < V_COUNT; ++v) canvas->fillCircle(212 + v * 7, 11, 2, v == view ? COL_LIME : COL_PANEL);
    canvas->setTextDatum(top_right);
    canvas->setTextColor(aud_in_ble ? COL_MAGENTA : aud_lock_ch ? COL_AMBER : COL_LIME);
    char b[12];
    if (aud_in_ble) snprintf(b, sizeof b, "BLE");
    else snprintf(b, sizeof b, "CH%02d", aud_cur_ch);
    canvas->drawString(b, 302, 3);
    if ((millis() / 400) % 2) canvas->fillCircle(311, 11, 3, COL_RED);
    int sx = (int)((millis() / 3) % (SCREEN_W + 60)) - 60;
    canvas->fillRect(0, 21, SCREEN_W, 1, COL_PANEL);
    canvas->fillRect(sx, 21, 60, 1, COL_LIME);
}

static void aud_footer(const char* hint) {
    canvas->setFont(&fonts::Font0);
    canvas->setTextDatum(bottom_center);
    canvas->setTextColor(COL_HINT);
    canvas->drawString(hint, 160, 239);
}

static void aud_draw_banner() {
    if (millis() > aud_banner_until || ((millis() / 250) % 2)) return;
    canvas->fillRect(0, 24, SCREEN_W, 24, COL_RED);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(middle_center);
    canvas->setTextColor(COL_WHITE);
    canvas->drawString(aud_banner, 160, 36);
}

static void aud_gauge(int cx, int cy) {
    for (int s = 0; s < 5; ++s) {
        float a0 = 180.0f + s * 36.0f + 1.5f, a1 = a0 + 33.0f;
        canvas->fillArc(cx, cy, 50, 38, a0, a1, s < aud_level ? LEVEL_COL[s + 1] : COL_PANEL);
    }
    float a = (180.0f + 36.0f * (aud_level - 0.5f)) * PI / 180.0f;
    canvas->drawWideLine(cx, cy, cx + 44 * cosf(a), cy + 44 * sinf(a), 2.5f, COL_WHITE);
    canvas->fillCircle(cx, cy, 4, COL_WHITE);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_center);
    canvas->setTextColor(LEVEL_COL[aud_level]);
    canvas->drawString(LEVEL_NAME[aud_level], cx, cy + 6);
    canvas->setFont(&fonts::Font0);
    canvas->setTextColor(COL_HINT);
    char b[24];
    uint32_t el = (millis() - aud_start_t) / 1000;
    snprintf(b, sizeof b, "T+%02lu:%02lu  %s", (unsigned long)(el / 60), (unsigned long)(el % 60), aud_ble_ok ? "WiFi+BLE" : "WiFi");
    canvas->drawString(b, cx, cy + 24);
}

// ---------------------------------------------------------------------------
//  Row models for the list views
// ---------------------------------------------------------------------------
struct Row { uint8_t ent; int16_t idx; int16_t key; };
static Row aud_rows[160];
static int aud_row_n = 0;

static void rows_cams() {
    aud_row_n = 0;
    uint32_t now = millis();
    for (int i = 0; i < AUD_MAX_STA && aud_row_n < 150; ++i) {
        AudSta& s = aud_sta[i];
        if (!s.used || now - s.seen > 180000) continue;
        uint8_t sc = cam_score(s);
        bool camcat = s.cat == CAT_CAMERA || s.cat == CAT_LPR || s.cat == CAT_POLICE;
        if (sc >= 15 || camcat) aud_rows[aud_row_n++] = {ENT_STA, (int16_t)i, (int16_t)sc};
    }
    for (int i = 0; i < aud_n && aud_row_n < 158; ++i) {
        AudAP& a = aud_ap[i];
        if (now - a.seen > 120000) continue;
        bool cam = a.cat == CAT_CAMERA || a.cat == CAT_LPR || strstr(a.device_class, "amera") || ssid_cam_hint(aud_name(a));
        if (!cam || sta_slot(a.bssid, false) >= 0) continue;          // already listed via its traffic
        aud_rows[aud_row_n++] = {ENT_AP, (int16_t)i, (int16_t)(a.cat == CAT_CAMERA || a.cat == CAT_LPR ? 45 : 25)};
    }
    std::sort(aud_rows, aud_rows + aud_row_n, [](const Row& x, const Row& y) { return x.key > y.key; });
}

static void rows_track() {
    aud_row_n = 0;
    uint32_t now = millis();
    for (int i = 0; i < aud_trk_n && aud_row_n < 150; ++i)
        if (now - aud_trk[i].seen < 180000)
            aud_rows[aud_row_n++] = {ENT_TRK, (int16_t)i, (int16_t)(places_count(aud_trk[i].places) * 100 + (aud_trk[i].kind == BK_FINDMY_SEP || aud_trk[i].kind == BK_FMDN_UTP ? 50 : 0) + 128 + aud_trk[i].best)};
    for (int i = 0; i < aud_n && aud_row_n < 155; ++i)
        if (is_following(aud_ap[i].places, aud_ap[i].first_seen, aud_ap[i].seen))
            aud_rows[aud_row_n++] = {ENT_AP, (int16_t)i, (int16_t)(places_count(aud_ap[i].places) * 100)};
    for (int i = 0; i < AUD_MAX_STA && aud_row_n < 158; ++i)
        if (aud_sta[i].used && is_following(aud_sta[i].places, aud_sta[i].first_seen, aud_sta[i].seen))
            aud_rows[aud_row_n++] = {ENT_STA, (int16_t)i, (int16_t)(places_count(aud_sta[i].places) * 100)};
    std::sort(aud_rows, aud_rows + aud_row_n, [](const Row& x, const Row& y) { return x.key > y.key; });
}

static void rows_leaks() {
    aud_row_n = 0;
    uint32_t now = millis();
    for (int i = 0; i < aud_probe_n; ++i)
        if (now - aud_probe[i].seen < 180000) aud_rows[aud_row_n++] = {ENT_PROBE, (int16_t)i, (int16_t)aud_probe[i].best};
    std::sort(aud_rows, aud_rows + aud_row_n, [](const Row& x, const Row& y) { return x.key > y.key; });
}

static void rows_nets() {
    aud_row_n = 0;
    uint32_t now = millis();
    for (int i = 0; i < aud_n; ++i)
        if (now - aud_ap[i].seen < 120000)
            aud_rows[aud_row_n++] = {ENT_AP, (int16_t)i, (int16_t)(ent_flag(ENT_AP, i) * 200 + 128 + aud_ap[i].best)};
    std::sort(aud_rows, aud_rows + aud_row_n, [](const Row& x, const Row& y) { return x.key > y.key; });
}

static const char* ent_label(uint8_t ent, int idx, char* b, size_t n) {
    switch (ent) {
        case ENT_AP:    snprintf(b, n, "%s", aud_name(aud_ap[idx])); break;
        case ENT_STA: { AudSta& s = aud_sta[idx]; sta_vendor(s); char m[18]; mac_str(s.mac, m);
                        snprintf(b, n, "%s %s", s.vendor, m + 9); break; }
        case ENT_TRK: { AudTrk& t = aud_trk[idx];
                        if (t.kind == BK_TESLA && t.name[0]) snprintf(b, n, "Tesla %s", t.name);
                        else snprintf(b, n, "%s", t.name[0] ? t.name : (t.kind ? BK_NAME[t.kind] : t.addr));
                        break; }
        case ENT_PROBE: { char m[18]; mac_str(aud_probe[idx].mac, m); snprintf(b, n, "%s%s", m, mac_random(aud_probe[idx].mac) ? " (rnd)" : ""); break; }
        default: b[0] = 0;
    }
    return b;
}
static int ent_rssi(uint8_t ent, int idx) {
    switch (ent) {
        case ENT_AP: return aud_ap[idx].rssi;
        case ENT_STA: return aud_sta[idx].rssi;
        case ENT_TRK: return aud_trk[idx].rssi;
        case ENT_PROBE: return aud_probe[idx].rssi;
    }
    return -127;
}

// ---------------------------------------------------------------------------
//  Views
// ---------------------------------------------------------------------------
static constexpr int AUD_ROW_TOP = 114, AUD_ROW_H = 28, AUD_ROWS = 4;
static constexpr int LIST_TOP2 = 26, LIST_H2 = 25, LIST_ROWS2 = 8;   // ends at y 226, clear of the footer

static void draw_sitrep(int scroll) {
    canvas->fillSprite(COL_BG);
    aud_header(VIEW_TITLE[V_SITREP], V_SITREP);
    aud_gauge(62, 82);
    uint32_t now = millis();
    int nets = 0, devs = 0, cams = 0, trks = 0;
    for (int i = 0; i < aud_n; ++i) if (now - aud_ap[i].seen < 120000) nets++;
    for (int i = 0; i < AUD_MAX_STA; ++i)
        if (aud_sta[i].used && now - aud_sta[i].seen < 120000) { devs++; if (aud_sta[i].score >= 45) cams++; }
    for (int i = 0; i < aud_trk_n; ++i) if (bk_is_tracker(aud_trk[i].kind) && now - aud_trk[i].seen < 120000) trks++;
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    int y = 26;
    char b[28], d1[12];
    auto stat = [&](const char* k, const char* v, uint16_t c) {
        canvas->setTextColor(COL_HINT); canvas->drawString(k, 128, y);
        canvas->setTextColor(c);        canvas->drawString(v, 220, y);
        y += 17;
    };
    snprintf(b, sizeof b, "%d / %d", nets, devs);                   stat("NETS/DEVS", b, COL_TEXT);
    snprintf(b, sizeof b, "%d", cams);                              stat("CAMERAS", b, cams ? COL_AMBER : COL_TEXT);
    snprintf(b, sizeof b, "%d", trks);                              stat("TRACKERS", b, trks ? COL_AMBER : COL_TEXT);
    CrowdEst ce; crowd_estimate(ce);
    snprintf(b, sizeof b, "~%d (%d-%d)", (int)lroundf(ce.est), (int)lroundf(ce.lo), (int)lroundf(ce.hi));
    stat("PEOPLE", b, COL_TEXT);
    if (aud_places_n > 1) snprintf(b, sizeof b, "%d (%s ago)", aud_places_n, dur_str(now - aud_place_changed_t, d1, sizeof d1));
    else snprintf(b, sizeof b, "1 (stationary)");
    stat("PLACES", b, COL_TEXT);

    if (aud_find_n == 0) {
        canvas->setTextDatum(middle_center);
        canvas->setTextColor(0x07E0);
        canvas->drawString("NO THREATS DETECTED", 160, 150);
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(COL_HINT);
        canvas->drawString(now - aud_start_t < 6000 ? "sweeping all channels..." : "monitoring...", 160, 172);
    }
    for (int r = 0; r < AUD_ROWS; ++r) {
        int fi = scroll + r;
        if (fi >= aud_find_n) break;
        AudFinding& f = aud_find[fi];
        int ry = AUD_ROW_TOP + r * AUD_ROW_H;
        canvas->fillRoundRect(4, ry, 312, AUD_ROW_H - 2, 4, COL_PANEL);
        canvas->fillRoundRect(8, ry + 4, 38, 18, 3, sev_col(f.sev));
        canvas->setFont(&fonts::Font0);
        canvas->setTextDatum(middle_center);
        canvas->setTextColor(COL_BLACK);
        canvas->drawString(SEV_TAG[f.sev], 27, ry + 13);
        canvas->setFont(&fonts::Font2);
        canvas->setTextDatum(top_left);
        canvas->setTextColor(sev_col(f.sev));
        char t[72], l[40];
        if (f.ent && f.idx >= 0) snprintf(t, sizeof t, "%s  %s", f.title, ent_label(f.ent, f.idx, l, sizeof l));
        else snprintf(t, sizeof t, "%s", f.title);
        draw_fit(t, 52, ry - 1, 258);
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(COL_HINT);
        draw_fit(f.detail, 52, ry + 16, 258);
    }
    aud_draw_banner();
    aud_footer("tap = intel   A reset   B next view   C exit");
    canvas->pushSprite(0, 0);
}

static void draw_list_view(int view, int scroll) {
    canvas->fillSprite(COL_BG);
    aud_header(VIEW_TITLE[view], view);
    uint32_t now = millis();
    char b[64], d1[12];
    if (!aud_row_n) {
        canvas->setFont(&fonts::Font2);
        canvas->setTextDatum(middle_center);
        canvas->setTextColor(COL_HINT);
        const char* empty = view == V_CAMS ? "no camera candidates yet"
                          : view == V_TRACK ? "no trackers or tails"
                          : view == V_LEAKS ? "no probe requests heard" : "listening...";
        canvas->drawString(empty, 160, 120);
    }
    for (int r = 0; r < LIST_ROWS2; ++r) {
        int li = scroll + r;
        if (li >= aud_row_n) break;
        Row& row = aud_rows[li];
        int ry = LIST_TOP2 + r * LIST_H2;
        canvas->fillRoundRect(4, ry, 312, LIST_H2 - 2, 3, COL_PANEL);
        int8_t fl = ent_flag(row.ent, row.idx);
        if (fl >= 0) canvas->fillRect(4, ry, 4, LIST_H2 - 2, sev_col((uint8_t)fl));
        canvas->setFont(&fonts::Font2);
        canvas->setTextDatum(top_left);
        canvas->setTextColor(COL_TEXT);
        if (view == V_CAMS) {
            int sc = row.key;
            canvas->fillRect(12, ry + 6, 40, 10, COL_BG);
            canvas->fillRect(12, ry + 6, sc * 40 / 100, 10, score_col(sc));
            draw_fit(ent_label(row.ent, row.idx, b, sizeof b), 58, ry + 3, 180);
            canvas->setFont(&fonts::Font0);
            canvas->setTextDatum(middle_right);
            canvas->setTextColor(COL_HINT);
            if (row.ent == ENT_STA) { snprintf(b, sizeof b, "%ukbps", sta_median_kbps(aud_sta[row.idx])); canvas->drawString(b, 280, ry + 11); }
        } else if (view == V_TRACK) {
            uint32_t fs = 0; uint16_t pl = 0;
            const char* tag = "";
            if (row.ent == ENT_TRK) { AudTrk& t = aud_trk[row.idx]; fs = t.first_seen; pl = t.places;
                                      tag = t.name[0] ? (t.kind ? BK_NAME[t.kind] : "BLE") : t.addr; }
            else if (row.ent == ENT_AP) { fs = aud_ap[row.idx].first_seen; pl = aud_ap[row.idx].places; tag = "network"; }
            else { fs = aud_sta[row.idx].first_seen; pl = aud_sta[row.idx].places; tag = "device"; }
            draw_fit(ent_label(row.ent, row.idx, b, sizeof b), 12, ry + 1, 200);
            canvas->setFont(&fonts::Font0);
            canvas->setTextColor(COL_HINT);
            char t2[64];
            snprintf(t2, sizeof t2, "%s | with you %s | %d place%s", tag, dur_str(now - fs, d1, sizeof d1),
                     places_count(pl), places_count(pl) == 1 ? "" : "s");
            draw_fit(t2, 12, ry + 16, 268);
        } else if (view == V_LEAKS) {
            AudProbe& p = aud_probe[row.idx];
            draw_fit(ent_label(row.ent, row.idx, b, sizeof b), 12, ry + 1, 220);
            canvas->setFont(&fonts::Font0);
            canvas->setTextColor(p.n ? COL_YELLOW : COL_HINT);
            char list[96] = "";
            for (int k = 0; k < p.n; ++k) { if (k) strncat(list, ", ", sizeof list - strlen(list) - 1); strncat(list, p.ssids[k], sizeof list - strlen(list) - 1); }
            draw_fit(p.n ? list : "(broadcast probes only)", 12, ry + 16, 250);
        } else {  // NETWORKS
            AudAP& a = aud_ap[row.idx];
            canvas->setTextColor(a.ssid[0] ? COL_TEXT : (a.revealed[0] ? COL_MAGENTA : COL_DIM));
            draw_fit(aud_name(a), 12, ry + 3, 148);
            canvas->fillRoundRect(166, ry + 3, 58, 16, 3, sec_col(a.sec));
            canvas->setFont(&fonts::Font0);
            canvas->setTextDatum(middle_center);
            canvas->setTextColor(COL_BLACK);
            canvas->drawString(SEC_NAME[a.sec], 195, ry + 11);
            canvas->setTextColor(COL_HINT);
            snprintf(b, sizeof b, "ch%d", a.ch);
            canvas->drawString(b, 246, ry + 11);
        }
        canvas->setFont(&fonts::Font0);
        canvas->setTextDatum(middle_right);
        canvas->setTextColor(COL_LIME);
        snprintf(b, sizeof b, "%d", ent_rssi(row.ent, row.idx));
        canvas->drawString(b, 310, ry + 11);
    }
    aud_draw_banner();
    aud_footer("tap = intel   swipe = scroll   B next view   C exit");
    canvas->pushSprite(0, 0);
}

static void draw_crowd() {
    canvas->fillSprite(COL_BG);
    aud_header(VIEW_TITLE[V_CROWD], V_CROWD);
    CrowdEst c; crowd_estimate(c);
    canvas->setTextDatum(top_left);
    canvas->setFont(&fonts::Font4);
    canvas->setTextSize(2);
    canvas->setTextColor(COL_LIME);
    char b[64];
    snprintf(b, sizeof b, "%d", (int)lroundf(c.est));
    canvas->drawString(b, 10, 26);
    canvas->setTextSize(1);
    canvas->setFont(&fonts::Font2);
    canvas->setTextColor(COL_TEXT);
    canvas->drawString(c.cat, 110, 30);
    canvas->setTextColor(COL_HINT);
    snprintf(b, sizeof b, "likely %d-%d people in radio range", (int)lroundf(c.lo), (int)lroundf(c.hi));
    canvas->drawString(b, 110, 48);
    snprintf(b, sizeof b, "~%d within ~10 m", c.near_est);
    canvas->drawString(b, 110, 64);

    int y = 88;
    auto row = [&](const char* k, const char* v) {
        canvas->setTextColor(COL_HINT); canvas->drawString(k, 10, y);
        canvas->setTextColor(COL_TEXT); canvas->drawString(v, 150, y);
        y += 16;
    };
    snprintf(b, sizeof b, "%d (%d close)", c.apple, c.apple_near);           row("Apple BLE devices", b);
    snprintf(b, sizeof b, "%d (%d Apple, %d other)", c.wifi, c.wifi_apple, c.wifi_other); row("WiFi probe devices", b);
    // 10-minute trend (one sample every 30 s)
    int gx = 10, gy = 176, gw = 300, gh = 34;
    canvas->drawRect(gx, gy - gh, gw, gh + 1, COL_PANEL);
    uint16_t mx = 1;
    for (int i = 0; i < aud_crowd_hist_n; ++i) mx = std::max(mx, aud_crowd_hist[i]);
    for (int i = 0; i < aud_crowd_hist_n; ++i) {
        int bh = aud_crowd_hist[i] * (gh - 2) / mx;
        canvas->fillRect(gx + 2 + i * 15, gy - bh, 12, bh, COL_TEAL);
    }
    canvas->setFont(&fonts::Font0);
    canvas->setTextColor(COL_HINT);
    canvas->drawString("last 10 min", gx + 2, gy - gh + 2);
    canvas->drawString("Phones/0.91 (Pew 2025) vs iPhones/0.58 (iOS share)", 10, 184);
    canvas->drawString("Probes grouped by IE fingerprint + sequence no.", 10, 194);
    canvas->drawString("Idle Androids rarely probe: count is a floor.", 10, 204);
    aud_draw_banner();
    aud_footer("A reset   B next view   C exit");
    canvas->pushSprite(0, 0);
}

static void draw_spectrum() {
    canvas->fillSprite(COL_BG);
    aud_header(VIEW_TITLE[V_SPECTRUM], V_SPECTRUM);
    canvas->setFont(&fonts::Font0);
    canvas->setTextDatum(top_left);
    canvas->setTextColor(COL_TEAL);    canvas->drawString("# networks", 8, 28);
    canvas->setTextColor(COL_LIME);    canvas->drawString("| frames", 80, 28);
    canvas->setTextColor(COL_MAGENTA); canvas->drawString("- noise", 136, 28);
    canvas->setTextColor(COL_RED);     canvas->drawString("^ kicks", 190, 28);
    int count[14] = {0};
    uint32_t now = millis();
    for (int i = 0; i < aud_n; ++i) if (now - aud_ap[i].seen < 120000 && aud_ap[i].ch <= 13) count[aud_ap[i].ch]++;
    int maxc = 1;
    for (int c = 1; c <= 13; ++c) maxc = std::max(maxc, count[c]);
    const int base = 206, top = 52, h = base - top;
    for (int c = 1; c <= 13; ++c) {
        int x = 8 + (c - 1) * 23, w = 19;
        int bh = count[c] * (h - 10) / maxc;
        canvas->fillRect(x, base - bh, w, bh, COL_TEAL);
        int ah = std::min(h, (int)(ch_activity[c] * 0.3f));
        canvas->fillRect(x + w / 2 - 1, base - ah, 3, ah, COL_LIME);
        if (ch_noise[c] < 0) canvas->fillRect(x, base - (constrain((int)ch_noise[c], -100, -60) + 100) * h / 40, w, 2, COL_MAGENTA);
        if (ch_deauth_score[c] >= 1.0f)
            canvas->fillTriangle(x + w / 2, top - 6, x + 3, top + 4, x + w - 3, top + 4, ch_deauth_score[c] >= 6.0f ? COL_RED : COL_AMBER);
        if (c == aud_cur_ch) canvas->drawRect(x - 1, top - 8, w + 2, base - top + 9, COL_LIME);
        canvas->setTextDatum(top_center);
        canvas->setTextColor(COL_HINT);
        char b[4]; snprintf(b, sizeof b, "%d", c);
        canvas->drawString(b, x + w / 2, base + 3);
    }
    aud_draw_banner();
    aud_footer("A reset   B next view   C exit");
    canvas->pushSprite(0, 0);
}

// ---------------------------------------------------------------------------
//  FOX HUNT — commit to one transmitter until it's found
// ---------------------------------------------------------------------------
struct FoxTarget {
    uint8_t ent;
    int     idx;
    bool    ble;
    uint8_t mac[6];
    char    addr[18];
    uint8_t ch;
    char    label[34];
};

static bool fox_target_for(uint8_t ent, int idx, FoxTarget& t) {
    memset(&t, 0, sizeof t);
    t.ent = ent; t.idx = idx;
    char b[40];
    ent_label(ent, idx, b, sizeof b);
    strncpy(t.label, b, sizeof t.label - 1);
    switch (ent) {
        case ENT_AP:    memcpy(t.mac, aud_ap[idx].bssid, 6); t.ch = aud_ap[idx].ch; return true;
        case ENT_STA:   memcpy(t.mac, aud_sta[idx].mac, 6);  t.ch = aud_sta[idx].ch; return true;
        case ENT_PROBE: memcpy(t.mac, aud_probe[idx].mac, 6); t.ch = 0; return true;    // probes hop: listen where we are
        case ENT_TRK:   if (!aud_ble_ok) return false; t.ble = true; strncpy(t.addr, aud_trk[idx].addr, 17); return true;
    }
    return false;
}

static void fox_hunt(const FoxTarget& t) {
    Serial.printf("FOX HUNT: %s\n", t.label);
    if (t.ble) { aud_ble_watch(t.addr, true); aud_set_hold(HOLD_BLE); }
    else {
        aud_set_hold(HOLD_WIFI);
        memcpy(aud_watch_mac, t.mac, 6);
        aud_watch_rssi = -127; aud_watch_t = 0; aud_watch_bytes = 0;
        aud_watch_on = true;
        aud_lock_ch = t.ch ? t.ch : aud_cur_ch;
    }

    canvas->fillSprite(COL_BLACK);
    aud_header("FOX HUNT // LOCKING ON");
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(middle_center);
    canvas->setTextColor(COL_LIME);
    canvas->drawString("hold still: zeroing compass", 160, 110);
    canvas->setTextColor(COL_HINT);
    canvas->drawString(t.label, 160, 132);
    canvas->pushSprite(0, 0);
    RadarHeading hd;
    radar_heading_calibrate(hd);

    static RadarSource fx;
    static uint32_t bin_t[RADAR_BINS];
    static bool     swept[RADAR_BINS];
    auto new_sweep = [&]() {
        memset(&fx, 0, sizeof fx);
        for (int b = 0; b < RADAR_BINS; ++b) { fx.rssi[b] = -127; bin_t[b] = 0; swept[b] = false; }
        fx.strongest = -127;
    };
    new_sweep();
    float ema = -127, peak = -127, peak_hd = 0;
    float trend_ring[12]; int tr_i = 0, tr_n = 0;
    uint32_t last_rx = 0, trend_t = 0, next_click = 0, last_draw = 0;
    bool mute = false;
    const float p1m = t.ble ? -59.0f : -40.0f, pl_n = t.ble ? 2.2f : 2.7f;

    for (;;) {
        M5.update();
        aud_tick();
        heading_tick(hd);
        uint32_t now = millis();
        float yaw = hd.yaw;
        int sb = (int)(fmodf(fmodf(yaw, 360.0f) + 360.0f, 360.0f) * RADAR_BINS / 360.0f) % RADAR_BINS;
        swept[sb] = true;

        int8_t r = t.ble ? aud_bwatch_rssi : aud_watch_rssi;
        uint32_t tr = t.ble ? aud_bwatch_t : aud_watch_t;
        if (tr && tr != last_rx && r > -127) {
            last_rx = tr;
            ema = ema < -126 ? r : ema * 0.7f + r * 0.3f;
            if (r > peak) { peak = r; peak_hd = yaw; }
            RadarSource& d = fx;
            if (d.hits[sb] == 0) d.rssi[sb] = r; else d.rssi[sb] = (int8_t)((d.rssi[sb] * 3 + r) / 4);
            if (d.hits[sb] < 255) d.hits[sb]++;
            if (r > d.strongest) d.strongest = r;
            bin_t[sb] = now;
        }
        for (int b = 0; b < RADAR_BINS; ++b)                    // forget readings older than 25 s: you've moved
            if (fx.hits[b] && now - bin_t[b] > 25000) { fx.hits[b] = 0; fx.rssi[b] = -127; }
        if (now - trend_t >= 250) {
            trend_t = now;
            trend_ring[tr_i] = ema; tr_i = (tr_i + 1) % 12; if (tr_n < 12) tr_n++;
        }
        float trend = (tr_n == 12 && ema > -126 && trend_ring[tr_i] > -126) ? ema - trend_ring[tr_i] : 0;
        bool fresh = last_rx && now - last_rx < 6000;

        // Geiger clicks: faster and higher as the signal climbs
        if (!mute && fresh && now >= next_click) {
            float x = constrain((ema + 95.0f) / 60.0f, 0.0f, 1.0f);
            M5.Speaker.tone(600 + x * 2400, 15);
            next_click = now + (uint32_t)(900 - x * 820);
        }

        if (M5.BtnC.wasClicked() || M5.BtnC.wasHold()) break;
        if (M5.BtnA.wasClicked()) mute = !mute;
        if (M5.BtnB.wasClicked()) { new_sweep(); peak = -127; }

        if (now - last_draw < 66) { delay(5); continue; }
        last_draw = now;

        canvas->fillSprite(COL_BG);
        char h[48];
        snprintf(h, sizeof h, "FOX // %s", t.label);
        aud_header(h);

        // --- left: signal ---
        canvas->setTextDatum(top_left);
        canvas->setFont(&fonts::Font4);
        canvas->setTextSize(2);
        canvas->setTextColor(fresh ? COL_LIME : COL_DIM);
        char b[32];
        if (ema > -126) snprintf(b, sizeof b, "%d", (int)lroundf(ema)); else snprintf(b, sizeof b, "--");
        canvas->drawString(b, 8, 28);
        canvas->setTextSize(1);
        canvas->setFont(&fonts::Font2);
        canvas->setTextColor(COL_HINT);
        canvas->drawString("dBm", 112, 58);

        int bw = 150, bx = 8, by = 86;
        canvas->fillRect(bx, by, bw, 12, COL_PANEL);
        float xs = ema > -126 ? constrain((ema + 95.0f) / 60.0f, 0.0f, 1.0f) : 0;
        canvas->fillRect(bx, by, (int)(bw * xs), 12, xs > 0.75f ? COL_RED : xs > 0.45f ? COL_AMBER : COL_LIME);
        if (peak > -126) canvas->fillRect(bx + (int)(bw * constrain((peak + 95.0f) / 60.0f, 0.0f, 1.0f)) - 1, by - 3, 3, 18, COL_WHITE);

        canvas->setFont(&fonts::Font2);
        if (!fresh) { canvas->setTextColor(COL_AMBER); canvas->drawString(last_rx ? "TARGET QUIET" : "WAITING FOR TARGET", 8, 104); }
        else if (trend > 2.0f)  { canvas->setTextColor(COL_LIME);  canvas->drawString("WARMER  ^", 8, 104); }
        else if (trend < -2.0f) { canvas->setTextColor(COL_RED);   canvas->drawString("COLDER  v", 8, 104); }
        else                    { canvas->setTextColor(COL_HINT);  canvas->drawString("STEADY", 8, 104); }

        canvas->setTextColor(COL_TEXT);
        if (ema > -126) {
            float dist = powf(10.0f, (p1m - ema) / (10.0f * pl_n));
            if (dist < 1.0f) snprintf(b, sizeof b, "< 1 m (rough)");
            else snprintf(b, sizeof b, "~%.0f m (rough)", dist);
            canvas->drawString(b, 8, 122);
        }
        if (peak > -126) {
            float rel = fmodf(fmodf(peak_hd - yaw, 360.0f) + 540.0f, 360.0f) - 180.0f;
            snprintf(b, sizeof b, "peak %d dBm %s %d", (int)peak, rel >= 0 ? "R" : "L", (int)fabsf(rel));
            canvas->setTextColor(COL_HINT);
            canvas->drawString(b, 8, 140);
        }
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(COL_HINT);
        snprintf(b, sizeof b, "heard %.1fs ago  %s", last_rx ? (now - last_rx) / 1000.0f : 0.0f,
                 t.ble ? "BLE" : (aud_lock_ch ? "ch locked" : ""));
        canvas->drawString(b, 8, 160);

        // --- right: bearing dial (heading-up) ---
        const int dx = 238, dy = 110, dr = 62;
        canvas->drawCircle(dx, dy, dr, COL_RING);
        canvas->drawCircle(dx, dy, dr - 1, COL_RING);
        int cov = 0;
        for (int k = 0; k < RADAR_BINS; ++k) {
            if (!swept[k]) continue;
            cov++;
            float a = ((k + 0.5f) * 360.0f / RADAR_BINS - yaw) * PI / 180.0f;
            uint16_t c = fx.hits[k] ? COL_TEAL : COL_PANEL;
            canvas->drawLine(dx + (dr - 6) * sinf(a), dy - (dr - 6) * cosf(a), dx + (dr - 1) * sinf(a), dy - (dr - 1) * cosf(a), c);
        }
        canvas->fillTriangle(dx - 5, dy - dr - 6, dx + 5, dy - dr - 6, dx, dy - dr + 2, COL_TEAL);   // you face here
        float bearing, pk;
        int bins_with = 0;
        for (int k = 0; k < RADAR_BINS; ++k) if (fx.hits[k]) bins_with++;
        bool have = bins_with >= 8 && cov >= RADAR_BINS / 2 && radar_estimate(fx, bearing, pk);
        canvas->setTextDatum(middle_center);
        if (have) {
            float rel = fmodf(fmodf(bearing - yaw, 360.0f) + 540.0f, 360.0f) - 180.0f;
            float a = rel * PI / 180.0f;
            canvas->drawWideLine(dx, dy, dx + (dr - 10) * sinf(a), dy - (dr - 10) * cosf(a), 4.0f, COL_RED);
            canvas->fillCircle(dx + (dr - 10) * sinf(a), dy - (dr - 10) * cosf(a), 6, COL_RED);
            canvas->setFont(&fonts::Font2);
            canvas->setTextColor(COL_WHITE);
            if (fabsf(rel) < 15) snprintf(b, sizeof b, "AHEAD");
            else snprintf(b, sizeof b, "%s %d", rel > 0 ? "RIGHT" : "LEFT", (int)fabsf(rel));
            canvas->drawString(b, dx, fabsf(rel) <= 90 ? dy + 26 : dy - 26);   // opposite side to the needle
        } else {
            canvas->setFont(&fonts::Font0);
            canvas->setTextColor(COL_HINT);
            canvas->drawString("turn a slow", dx, dy - 14);
            canvas->drawString("full circle", dx, dy - 2);
            snprintf(b, sizeof b, "%d deg", cov * 360 / RADAR_BINS);
            canvas->drawString(b, dx, dy + 16);
        }
        if (have) canvas->fillCircle(dx, dy, 3, COL_WHITE);

        // --- close-range guidance ---
        if (fresh && ema > -45) {
            canvas->fillRoundRect(4, 176, 312, 44, 5, COL_RED);
            canvas->setFont(&fonts::Font2);
            canvas->setTextDatum(top_left);
            canvas->setTextColor(COL_WHITE);
            canvas->drawString("CLOSE: within a couple of metres", 10, 178);
            canvas->setFont(&fonts::Font0);
            canvas->drawString("Sweep at arm's length: vents, clocks, chargers,", 10, 198);
            canvas->drawString("smoke alarms, bags, wheel wells. White mark = peak.", 10, 208);
        } else {
            canvas->setFont(&fonts::Font0);
            canvas->setTextDatum(top_left);
            canvas->setTextColor(COL_HINT);
            canvas->drawString("Hold the Core2 flat against your chest: your body", 8, 184);
            canvas->drawString("shadows the signal, so it peaks when you FACE the", 8, 194);
            canvas->drawString("source. Walk toward the arrow; B re-sweeps.", 8, 204);
        }
        aud_footer(mute ? "A unmute   B new sweep   C end hunt" : "A mute   B new sweep   C end hunt");
        canvas->pushSprite(0, 0);
    }

    if (t.ble) aud_ble_watch("", false);
    aud_watch_on = false;
    aud_lock_ch = 0;
    aud_set_hold(HOLD_NONE);
    M5.Speaker.stop();
}

// ---------------------------------------------------------------------------
//  CAMERA CHALLENGE — does this device react when you move / flash at it?
// ---------------------------------------------------------------------------
static void cam_challenge(const uint8_t* mac, uint8_t ch, const char* label) {
    // choose stimulus
    canvas->fillSprite(COL_BLACK);
    aud_header("CHALLENGE // CONFIRM CAMERA");
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    canvas->setTextColor(COL_TEXT);
    canvas->drawString(label, 8, 30);
    canvas->setTextColor(COL_LIME);
    canvas->drawString("A  WAVE test", 8, 60);
    canvas->setFont(&fonts::Font0);
    canvas->setTextColor(COL_HINT);
    canvas->drawString("Stand where a camera could see you. On RED wave", 20, 80);
    canvas->drawString("your arms, on BLACK freeze. Finds room cameras.", 20, 90);
    canvas->setFont(&fonts::Font2);
    canvas->setTextColor(COL_LIME);
    canvas->drawString("B  SCREEN test", 8, 112);
    canvas->setFont(&fonts::Font0);
    canvas->setTextColor(COL_HINT);
    canvas->drawString("Hold the screen ~1 m from a suspect object", 20, 132);
    canvas->drawString("(smoke alarm, clock, charger). Dark room is best.", 20, 142);
    canvas->drawString("Takes 15 s, radio parked on this device's channel.", 8, 170);
    aud_footer("A wave   B screen   C cancel");
    canvas->pushSprite(0, 0);
    int mode = -1;
    while (mode < 0) {
        M5.update();
        aud_tick();
        if (M5.BtnA.wasClicked()) mode = 0;
        if (M5.BtnB.wasClicked()) mode = 1;
        if (M5.BtnC.wasClicked()) return;
        delay(10);
    }

    aud_set_hold(HOLD_WIFI);                           // no BLE windows mid-test: clean byte counts
    memcpy(aud_watch_mac, mac, 6);
    aud_watch_bytes = 0;
    aud_watch_on = true;
    aud_lock_ch = ch ? ch : aud_cur_ch;

    static const uint8_t pat[10] = {1, 0, 1, 1, 0, 1, 0, 0, 1, 0};
    const uint32_t CHIP = 1500, GUARD = 400;
    float y[10];
    for (int c = 3; c > 0; --c) {                      // countdown
        uint32_t t0 = millis();
        while (millis() - t0 < 1000) {
            M5.update(); aud_tick();
            canvas->fillSprite(COL_BLACK);
            canvas->setFont(&fonts::Font4);
            canvas->setTextSize(2);
            canvas->setTextDatum(middle_center);
            canvas->setTextColor(COL_AMBER);
            char b[4]; snprintf(b, sizeof b, "%d", c);
            canvas->drawString(b, 160, 110);
            canvas->setTextSize(1);
            canvas->pushSprite(0, 0);
            delay(30);
        }
    }
    M5.Display.setBrightness(255);
    for (int k = 0; k < 10; ++k) {
        uint32_t t0 = millis();
        uint32_t b0 = 0;
        bool armed = false;
        if (pat[k] && mode == 0) { M5.Power.setVibration(180); }
        while (millis() - t0 < CHIP) {
            M5.update(); aud_tick();
            uint32_t el = millis() - t0;
            if (!armed && el >= GUARD) { b0 = aud_watch_bytes; armed = true; }
            if (mode == 0 && el > 200) M5.Power.setVibration(0);
            if (pat[k]) {
                if (mode == 0) {
                    canvas->fillSprite(COL_RED);
                    canvas->setFont(&fonts::Font4);
                    canvas->setTextDatum(middle_center);
                    canvas->setTextColor(COL_WHITE);
                    canvas->drawString("MOVE!", 160, 110);
                } else {
                    int off = (int)((millis() / 25) % 40);    // fast moving high-contrast bars
                    for (int x = -40; x < SCREEN_W; x += 40) {
                        canvas->fillRect(x + off, 0, 20, SCREEN_H, COL_WHITE);
                        canvas->fillRect(x + off + 20, 0, 20, SCREEN_H, COL_BLACK);
                    }
                }
            } else {
                canvas->fillSprite(COL_BLACK);
                if (mode == 0) {
                    canvas->setFont(&fonts::Font4);
                    canvas->setTextDatum(middle_center);
                    canvas->setTextColor(COL_DIM);
                    canvas->drawString("FREEZE", 160, 110);
                }
            }
            canvas->fillRect(0, SCREEN_H - 4, SCREEN_W * (k * CHIP + el) / (10 * CHIP), 4, COL_LIME);
            canvas->pushSprite(0, 0);
            delay(15);
        }
        y[k] = (float)(aud_watch_bytes - b0);
    }
    M5.Power.setVibration(0);
    M5.Display.setBrightness(180);
    aud_watch_on = false;
    aud_lock_ch = 0;
    aud_set_hold(HOLD_NONE);

    // correlation between stimulus and the device's upload
    float mx = 0, my = 0;
    for (int k = 0; k < 10; ++k) { mx += pat[k]; my += y[k]; }
    mx /= 10; my /= 10;
    float sxy = 0, sxx = 0, syy = 0, on = 0, off = 0;
    for (int k = 0; k < 10; ++k) {
        sxy += (pat[k] - mx) * (y[k] - my); sxx += (pat[k] - mx) * (pat[k] - mx); syy += (y[k] - my) * (y[k] - my);
        if (pat[k]) on += y[k]; else off += y[k];
    }
    float rr = (sxx > 0 && syy > 0) ? sxy / sqrtf(sxx * syy) : 0;
    float ratio = off > 0 ? on / off : (on > 0 ? 99.0f : 1.0f);
    const char* verdict; uint16_t vc;
    if (rr >= 0.65f && ratio >= 1.3f)      { verdict = "CONFIRMED: IT SEES YOU"; vc = COL_RED; }
    else if (rr >= 0.4f && ratio >= 1.15f) { verdict = "PROBABLE: REACTS TO YOU"; vc = COL_AMBER; }
    else if (on + off < 2000)              { verdict = "SILENT: NO UPLOAD"; vc = COL_HINT; }
    else                                   { verdict = "NO REACTION HERE"; vc = COL_LIME; }
    Serial.printf("CHALLENGE %s r=%.2f ratio=%.2f bytes on=%.0f off=%.0f\n", label, rr, ratio, on, off);

    canvas->fillSprite(COL_BG);
    aud_header("CHALLENGE // RESULT");
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    canvas->setTextColor(vc);
    canvas->drawString(verdict, 8, 28);
    canvas->setTextColor(COL_TEXT);
    char b[64];
    snprintf(b, sizeof b, "correlation %.2f   upload x%.1f when %s", rr, ratio, mode == 0 ? "moving" : "flashing");
    canvas->setFont(&fonts::Font0);
    canvas->drawString(b, 8, 50);
    float ymax = 1;
    for (int k = 0; k < 10; ++k) ymax = std::max(ymax, y[k]);
    for (int k = 0; k < 10; ++k) {
        int x = 14 + k * 30, hgt = (int)(110 * y[k] / ymax);
        canvas->fillRect(x, 70, 24, 6, pat[k] ? COL_RED : COL_PANEL);       // stimulus
        canvas->fillRect(x, 196 - hgt, 24, hgt, pat[k] ? COL_AMBER : COL_TEAL);
    }
    canvas->drawString("top: stimulus on/off   bars: bytes the device sent", 8, 202);
    canvas->drawString("Battery cams can lag: a late jump still counts.", 8, 214);
    aud_footer("any button = back");
    canvas->pushSprite(0, 0);
    for (;;) {
        M5.update(); aud_tick();
        if (M5.BtnA.wasClicked() || M5.BtnB.wasClicked() || M5.BtnC.wasClicked()) break;
        int tx, ty; if (screen_tap(tx, ty)) break;
        delay(10);
    }
}

// ---------------------------------------------------------------------------
//  INTEL
// ---------------------------------------------------------------------------
static void aud_locate_radar(int ap) {                 // classic rotational radar on an AP
    AudAP& a = aud_ap[ap];
    mac_str(a.bssid, radar_target_id);
    copy_ascii(radar_target_name, aud_name(a), sizeof radar_target_name);
    radar_target_ch = a.ch;
    aud_ble_stop();
    aud_wifi_stop();
    M5.Power.setVibration(0);
    radar_run(true);
    radar_target_id[0] = 0; radar_target_name[0] = 0; radar_target_ch = 0;
    aud_in_ble = false; aud_hold = HOLD_NONE; aud_sweeps = 0;
    aud_wifi_start();
    aud_ble_start();
}

static void draw_intel(uint8_t ent, int idx, const AudFinding* f) {
    canvas->fillSprite(COL_BG);
    char h[40];
    snprintf(h, sizeof h, "INTEL // %s", f ? SEV_TAG[f->sev] : "TARGET");
    aud_header(h);
    int y = 25;
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(top_left);
    if (f) {
        canvas->setTextColor(sev_col(f->sev));
        canvas->drawString(f->title, 8, y);
        y += 16;
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(COL_TEXT);
        y += 10 * draw_wrap(f->detail, 8, y, 304, 10, 3) + 4;
        canvas->setFont(&fonts::Font2);
    }
    char b[64], d1[16];
    uint32_t now = millis();
    auto line = [&](const char* k, const char* v, uint16_t c) {
        if (y > 206) return;
        canvas->setTextColor(COL_HINT); canvas->drawString(k, 8, y);
        canvas->setTextColor(c);        draw_fit(v, 82, y, 232);
        y += 16;
    };
    if (ent == ENT_AP && idx >= 0) {
        AudAP& a = aud_ap[idx];
        line("NAME", aud_name(a), a.revealed[0] && a.hidden ? COL_MAGENTA : COL_TEXT);
        mac_str(a.bssid, b);                                         line("BSSID", b, friendly_has(b) ? 0x07E0 : COL_TEXT);
        snprintf(b, sizeof b, "%s | %s", a.vendor, a.device_class);  line("MAKER", b, a.cat ? COL_AMBER : COL_TEXT);
        snprintf(b, sizeof b, "%s ch%d%s%s%s%s", SEC_NAME[a.sec], a.ch, (a.flags & APF_PMF_REQ) ? " PMF" : (a.flags & APF_PMF_CAP) ? " pmf" : "",
                 (a.flags & APF_WPS) ? ((a.flags & APF_WPS_LOCKED) ? " WPS(lck)" : " WPS!") : "", (a.flags & APF_TKIP) ? " TKIP!" : "",
                 a.hidden ? " hidden" : "");
        line("CRYPTO", b, sec_col(a.sec));
        int clients = 0;
        for (int i = 0; i < AUD_MAX_STA; ++i) if (aud_sta[i].used && !aud_sta[i].is_ap && !memcmp(aud_sta[i].bssid, a.bssid, 6)) clients++;
        snprintf(b, sizeof b, "%s | %d clients | %d place%s", a.tsf ? uptime_str(a.tsf, d1, sizeof d1) : "?", clients,
                 places_count(a.places), places_count(a.places) == 1 ? "" : "s");
        line("UPTIME", b, COL_TEXT);
        if (a.flags & APF_RID) {
            snprintf(b, sizeof b, "%.5f,%.5f %dm", a.rid.lat * 1e-7, a.rid.lon * 1e-7, a.rid.alt_m); line("DRONE AT", b, COL_RED);
            if (a.rid.have & 4) { snprintf(b, sizeof b, "%.5f,%.5f", a.rid.op_lat * 1e-7, a.rid.op_lon * 1e-7); line("PILOT AT", b, COL_RED); }
        }
        snprintf(b, sizeof b, "%d dBm (peak %d)  %s ago", a.rssi, a.best, dur_str(now - a.seen, d1, sizeof d1));
        line("SIGNAL", b, COL_LIME);
    } else if (ent == ENT_STA && idx >= 0) {
        AudSta& s = aud_sta[idx];
        char why[120];
        uint8_t sc = cam_score(s, why, sizeof why);
        mac_str(s.mac, b);                                           line(s.is_ap ? "AP MAC" : "MAC", b, friendly_has(b) ? 0x07E0 : COL_TEXT);
        snprintf(b, sizeof b, s.cat ? "%s | %s" : "%s%s", s.vendor, s.cat ? CAT_NAME[s.cat] : "");
        line("MAKER", b, s.cat ? COL_AMBER : COL_TEXT);
        int ai = aud_find_ap(s.bssid);
        line("ON NET", ai >= 0 ? aud_name(aud_ap[ai]) : "?", COL_TEXT);
        snprintf(b, sizeof b, "~%u kbps | up %luK down %luK", sta_median_kbps(s), (unsigned long)(s.tx_tot / 1024), (unsigned long)(s.rx_tot / 1024));
        line("TRAFFIC", b, COL_TEXT);
        snprintf(b, sizeof b, "%d / 100", sc);                        line("SCORE", b, score_col(sc));
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(COL_HINT);
        y += 10 * draw_wrap(why[0] ? why : "no camera traits", 82, y, 232, 10, 3) + 2;
        canvas->setFont(&fonts::Font2);
        snprintf(b, sizeof b, "%d dBm (peak %d) | %d place%s", s.rssi, s.best, places_count(s.places), places_count(s.places) == 1 ? "" : "s");
        line("SIGNAL", b, COL_LIME);
    } else if (ent == ENT_TRK && idx >= 0) {
        AudTrk& t = aud_trk[idx];
        line("TYPE", t.kind ? BK_NAME[t.kind] : "BLE device", t.kind ? COL_AMBER : COL_TEXT);
        line("ADDR", t.addr, friendly_has(t.addr) ? 0x07E0 : COL_TEXT);
        snprintf(b, sizeof b, "%s %s", t.name, t.cls);
        if (t.name[0] || t.cls[0]) line("ID", b, COL_TEXT);
        if (t.kind == BK_FINDMY_SEP) {
            static const char* const bat[] = {"full", "medium", "low", "critical"};
            line("BATTERY", bat[(t.status >> 6) & 3], COL_TEXT);
        }
        snprintf(b, sizeof b, "%s | %d place%s | %u sightings", dur_str(now - t.first_seen, d1, sizeof d1),
                 places_count(t.places), places_count(t.places) == 1 ? "" : "s", t.sightings);
        line("WITH YOU", b, places_count(t.places) >= 2 ? COL_RED : COL_TEXT);
        if (t.kind == BK_RID) {
            snprintf(b, sizeof b, "%.5f,%.5f %dm", t.rid.lat * 1e-7, t.rid.lon * 1e-7, t.rid.alt_m); line("DRONE AT", b, COL_RED);
            if (t.rid.have & 4) { snprintf(b, sizeof b, "%.5f,%.5f", t.rid.op_lat * 1e-7, t.rid.op_lon * 1e-7); line("PILOT AT", b, COL_RED); }
        }
        snprintf(b, sizeof b, "%d dBm (peak %d)", t.rssi, t.best);     line("SIGNAL", b, COL_LIME);
    } else if (ent == ENT_PROBE && idx >= 0) {
        AudProbe& p = aud_probe[idx];
        mac_str(p.mac, b);                                           line("MAC", b, COL_TEXT);
        line("TYPE", mac_random(p.mac) ? "randomized (modern phone)" : "fixed MAC (trackable!)", mac_random(p.mac) ? COL_TEXT : COL_AMBER);
        snprintf(b, sizeof b, "%d dBm (peak %d) | %d place%s", p.rssi, p.best, places_count(p.places), places_count(p.places) == 1 ? "" : "s");
        line("SIGNAL", b, COL_LIME);
        canvas->setTextColor(COL_HINT);
        canvas->drawString("REVEALS", 8, y);
        canvas->setTextColor(COL_YELLOW);
        for (int k = 0; k < p.n && y <= 206; ++k) { draw_fit(p.ssids[k], 82, y, 232); y += 16; }
        if (!p.n) { canvas->setTextColor(COL_HINT); canvas->drawString("no saved names (good opsec)", 82, y); }
    }
    bool challenge = ent == ENT_STA || (ent == ENT_AP && idx >= 0 && sta_slot(aud_ap[idx].bssid, false) >= 0);
    aud_draw_banner();
    aud_footer(challenge ? "A HUNT  B CHALLENGE  hold B friendly  C back"
                         : (ent == ENT_AP ? "A HUNT  hold A radar  hold B friendly  C back" : "A HUNT  hold B friendly  C back"));
    canvas->pushSprite(0, 0);
}

static void ent_id(uint8_t ent, int idx, char* out) {
    out[0] = 0;
    if (ent == ENT_AP) mac_str(aud_ap[idx].bssid, out);
    else if (ent == ENT_STA) mac_str(aud_sta[idx].mac, out);
    else if (ent == ENT_PROBE) mac_str(aud_probe[idx].mac, out);
    else if (ent == ENT_TRK) { strncpy(out, aud_trk[idx].addr, 17); out[17] = 0; }
}

static void aud_intel(uint8_t ent, int idx, int finding) {
    AudFinding fc;
    bool has_f = finding >= 0 && finding < aud_find_n;
    if (has_f) { fc = aud_find[finding]; ent = fc.ent; idx = fc.idx; }
    else if (ent && idx >= 0) {                       // attach the worst finding about this entity
        for (int k = 0; k < aud_find_n; ++k) if (aud_find[k].ent == ent && aud_find[k].idx == idx) { fc = aud_find[k]; has_f = true; break; }
    }
    uint32_t last = 0;
    char toast[32] = ""; uint32_t toast_t = 0;
    for (;;) {
        M5.update();
        aud_tick();
        if (M5.BtnC.wasClicked() || M5.BtnC.wasHold()) break;
        int tx, ty;
        if (screen_tap(tx, ty)) break;
        if (ent && idx >= 0) {
            if (M5.BtnA.wasClicked()) {
                FoxTarget t;
                if (fox_target_for(ent, idx, t)) fox_hunt(t);
                else { snprintf(toast, sizeof toast, "BLE is off: can't hunt"); toast_t = millis(); }
                last = 0;
            }
            if (M5.BtnA.wasHold() && ent == ENT_AP) { aud_locate_radar(idx); last = 0; }
            if (M5.BtnB.wasClicked()) {
                if (ent == ENT_STA) { char l[40]; cam_challenge(aud_sta[idx].mac, aud_sta[idx].ch, ent_label(ent, idx, l, sizeof l)); last = 0; }
                else if (ent == ENT_AP && sta_slot(aud_ap[idx].bssid, false) >= 0) { cam_challenge(aud_ap[idx].bssid, aud_ap[idx].ch, aud_name(aud_ap[idx])); last = 0; }
            }
            if (M5.BtnB.wasHold()) {
                char id[18]; ent_id(ent, idx, id);
                bool on = friendly_toggle(id);
                snprintf(toast, sizeof toast, on ? "marked FRIENDLY" : "friendly removed");
                toast_t = millis();
                aud_build_findings();
                last = 0;
            }
        }
        if (millis() - last > 400) {
            last = millis();
            draw_intel(ent, idx, has_f ? &fc : nullptr);
            if (toast_t && millis() - toast_t < 1500) {
                canvas->fillRoundRect(60, 100, 200, 30, 6, COL_LIME);
                canvas->setFont(&fonts::Font2);
                canvas->setTextDatum(middle_center);
                canvas->setTextColor(COL_BLACK);
                canvas->drawString(toast, 160, 115);
                canvas->pushSprite(0, 0);
            }
        }
        delay(10);
    }
}

static void aud_intro() {
    for (int i = 0; i <= 20; ++i) {
        canvas->fillSprite(COL_BLACK);
        canvas->setTextSize(1);
        canvas->setFont(&fonts::Font2);
        canvas->setTextDatum(middle_center);
        canvas->setTextColor(COL_LIME);
        canvas->drawString("SIGINT FIELD KIT", 160, 48);
        canvas->setFont(&fonts::Font0);
        canvas->setTextColor(COL_HINT);
        canvas->drawString("WIFI+BLE THREAT AUDIT // PASSIVE // NO EMISSIONS", 160, 68);
        canvas->setTextDatum(top_left);
        canvas->setTextColor(COL_TEAL);
        for (int l = 0; l < 6; ++l) {
            char hex[56];
            int n = 0;
            for (int k = 0; k < 12 && n < 50; ++k) n += snprintf(hex + n, sizeof hex - n, "%02X ", (unsigned)random(256));
            canvas->drawString(hex, 52, 92 + l * 11);
        }
        canvas->drawRect(60, 176, 200, 10, COL_TEAL);
        canvas->fillRect(62, 178, 196 * i / 20, 6, COL_LIME);
        canvas->setTextDatum(middle_center);
        canvas->setTextColor(COL_HINT);
        int sigs = (int)(sizeof kIntelMam / sizeof kIntelMam[0]);
        for (int k = 0; k < kIntelBrandCount; ++k) sigs += kIntelBrands[k].n;
        char ld[48];
        snprintf(ld, sizeof ld, "LOADING %d HARDWARE SIGNATURES...", sigs);
        canvas->drawString(ld, 160, 198);
        canvas->pushSprite(0, 0);
        delay(35);
    }
    canvas->fillRect(40, 100, 240, 46, COL_BLACK);
    canvas->drawRect(40, 100, 240, 46, COL_RED);
    canvas->drawRect(41, 101, 238, 44, COL_RED);
    canvas->setFont(&fonts::Font2);
    canvas->setTextDatum(middle_center);
    canvas->setTextColor(COL_LIME);
    canvas->drawString("CLEARANCE GRANTED", 160, 114);
    canvas->setTextColor(COL_RED);
    canvas->drawString("EYES ONLY", 160, 132);
    canvas->pushSprite(0, 0);
    M5.Power.setVibration(150);
    delay(120);
    M5.Power.setVibration(0);
    delay(500);
}
