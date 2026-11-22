/**
 * threat_audit.h — Threat Audit (SITREP): passive WiFi + BLE counter-surveillance.
 * Included once from main.cpp after the radar (it reuses the canvas, input
 * helpers, heading tracker, bearing estimator and the radar itself).
 *
 *   intel_db.h        833 maker prefixes: cameras, police/LPR, drones, attack kit
 *   audit_wifi.h      monitor-mode engine (APs, traffic, probes, deauth, Remote ID)
 *   audit_ble.h       passive BLE engine (trackers, Remote ID, Flipper, spam)
 *   audit_analysis.h  places, following, camera score, findings, friendly list
 *   audit_ui.h        views, intel, FOX HUNT, CHALLENGE
 */
#pragma once
#include "intel_db.h"
#include "audit_wifi.h"
#include "audit_ble.h"
#include "audit_analysis.h"
#include "audit_ui.h"
#include "audit_sense.h"

static void threat_audit_run() {
    Serial.println("audit: start");
    if (!aud_ap)    aud_ap    = (AudAP*)radar_alloc_mem(sizeof(AudAP) * AUD_MAX_AP);
    if (!aud_sta)   aud_sta   = (AudSta*)radar_alloc_mem(sizeof(AudSta) * AUD_MAX_STA);
    if (!aud_probe) aud_probe = (AudProbe*)radar_alloc_mem(sizeof(AudProbe) * AUD_MAX_PROBE);
    if (!aud_trk)   aud_trk   = (AudTrk*)radar_alloc_mem(sizeof(AudTrk) * AUD_MAX_TRK);
    if (!aud_q)     aud_q     = xQueueCreate(128, sizeof(AudFrame));
    if (!aud_ap || !aud_sta || !aud_probe || !aud_trk || !aud_q) {
        show_message("audit: out of memory", COL_RED);
        delay(1500);
        return;
    }
    intel_load_sd();
    friendly_load();
    aud_reset();
    aud_intro();
    aud_in_ble = false; aud_hold = HOLD_NONE; aud_sweeps = 0; aud_lock_ch = 0;
    aud_wifi_start();
    aud_ble_start();
    log_heap("audit");

    int view = V_SITREP;
    int scroll[V_COUNT] = {0};
    uint32_t last_draw = 0;
    for (;;) {
        M5.update();
        aud_tick();

        if (M5.BtnC.wasClicked() || M5.BtnC.wasHold()) break;
        if (M5.BtnB.wasClicked()) {
            int next = (view + 1) % V_COUNT;
            if (view == V_SENSE) sense_end();
            if (next == V_SENSE) { draw_sense(); sense_begin(); }
            view = next;
            last_draw = 0;
        }
        if (view == V_SENSE) {
            sense_tick();
            if (M5.BtnA.wasClicked()) sense_armed = !sense_armed;
            if (M5.BtnA.wasHold()) sense_sweep_toggle();
        } else if (M5.BtnA.wasClicked() && (view == V_SITREP || view == V_SPECTRUM || view == V_CROWD)) {
            aud_reset(); memset(scroll, 0, sizeof scroll);
        }

        // rebuild the row model for list views
        switch (view) {
            case V_CAMS:  rows_cams();  break;
            case V_TRACK: rows_track(); break;
            case V_LEAKS: rows_leaks(); break;
            case V_NETS:  rows_nets();  break;
            default: break;
        }
        int rows  = view == V_SITREP ? AUD_ROWS : LIST_ROWS2;
        int total = view == V_SITREP ? aud_find_n : aud_row_n;
        auto t = M5.Touch.getDetail();
        if ((t.wasFlicked() || t.wasDragged()) && t.base_y < SCREEN_H && view != V_SPECTRUM && view != V_CROWD && view != V_SENSE) {
            int dy = t.distanceY();
            if (dy < -20) scroll[view] += rows;
            else if (dy > 20) scroll[view] -= rows;
        }
        scroll[view] = constrain(scroll[view], 0, std::max(0, total - rows));

        int tx, ty;
        if (screen_tap(tx, ty)) {
            if (view == V_SITREP && ty >= AUD_ROW_TOP && ty < AUD_ROW_TOP + AUD_ROWS * AUD_ROW_H) {
                int fi = scroll[view] + (ty - AUD_ROW_TOP) / AUD_ROW_H;
                if (fi < aud_find_n) { aud_intel(ENT_NONE, -1, fi); last_draw = 0; }
            } else if (view != V_SITREP && view != V_SPECTRUM && view != V_CROWD && view != V_SENSE && ty >= LIST_TOP2 && ty < LIST_TOP2 + LIST_ROWS2 * LIST_H2) {
                int li = scroll[view] + (ty - LIST_TOP2) / LIST_H2;
                if (li < aud_row_n) { Row r = aud_rows[li]; aud_intel(r.ent, r.idx, -1); last_draw = 0; }
            }
        }

        if (millis() - last_draw >= 90) {
            last_draw = millis();
            if (view == V_SITREP) draw_sitrep(scroll[view]);
            else if (view == V_SPECTRUM) draw_spectrum();
            else if (view == V_CROWD) draw_crowd();
            else if (view == V_SENSE) draw_sense();
            else draw_list_view(view, scroll[view]);
        }
        delay(5);
    }
    if (view == V_SENSE) sense_end();
    aud_set_hold(HOLD_NONE);
    aud_ble_stop();
    aud_wifi_stop();
    M5.Power.setVibration(0);
    Serial.println("audit: stop");
}
