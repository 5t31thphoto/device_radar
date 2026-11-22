# DeviceRadar — Mantis Edition

Standalone **WiFi + BLE rotational radar** for **M5Stack Core2**, using **M5Unified**.

Ported from the Fox Voice Companion radar tools. Single merged binary with an
on-device menu. The pixel mantis is the mascot: it sits in the centre of every
radar sweep, owns the splash screen, and is the favicon of the web flasher.

**Theme:** `#007373` teal · `#5d005d` purple · lime green · dark grey

---

## What it does

1. Choose **WiFi Radar**, **BLE Radar** or **Threat Audit** from the menu.
2. Hold still for gyro bias calibration.
3. Slowly turn in place (~20 s full circle). Keep the **green** needle on the
   **red** target. Scans run in the background.
4. After one full turn the map is live — devices plotted by estimated bearing;
   radius is relative RSSI only (not metres). The triangle at the top is the
   direction you're facing; the map turns as you turn.
5. **BtnA** = rescan · **BtnB** = device list · **BtnC** = exit · tap a dot to
   see what it is.

**Tips for good bearings:** hold the Core2 in front of your chest — your body
blocking the signal from behind is what makes the direction show up. Turn at
a steady pace. If dots look mirrored left/right, set `YAW_SIGN` to `-1.0f` at
the top of `src/main.cpp`.

## Threat Audit (SITREP)

Third menu item. Passive counter-surveillance: WiFi monitor mode (all 13
channels) plus a passive BLE scan. Nothing is transmitted.

**What it finds, and how**

- **Cameras that never beacon.** Every WiFi camera has to *send* video, so
  each transmitter's upload is measured per channel. Score = maker prefix
  (833 registered prefixes: Hikvision, Dahua, Ezviz, Uniview, Axis, Ring, Wyze,
  Arlo, Blink, Nest, Reolink, Lorex, Swann, SimpliSafe, Imilab, Flock, Axon,
  WatchGuard, Motorola Solutions, DJI, Cradlepoint; Espressif and TP-Link as a
  soft "cam-capable" flag) + sustained steady upload + upload/download ratio +
  proximity, minus phone-style random MACs. **CHALLENGE** confirms a candidate:
  wave on cue (or flash the screen at a suspect object) and it correlates the
  device's upload with your stimulus.
- **Anything following you.** The strongest fixed access points form a
  location fingerprint; when it changes you've moved (no GPS). Any tracker,
  network, device, phone or Tesla (its BLE name is derived from its VIN) seen
  at 2+ places over 5+ min is flagged.
- **Trackers:** AirTag / Find My in lost mode, Google Find My tags (including
  anti-stalking mode), SmartTag, Tile.
- **Attacks:** deauth floods, spoofed deauths (sequence numbers that don't
  match the real AP), cloned BSSIDs (beacon clock jumps), evil twins,
  impersonators (fresh copy, different radio stack), Karma, beacon floods,
  BLE pop-up spam, Pineapple, Pwnagotchi, Flipper Zero.
- **Other watchers:** camera glasses (Meta/Ray-Ban, Snap company IDs), drone
  Remote ID with drone and pilot coordinates, plate readers, police gear,
  vehicle routers, dashcam and spy-cam hotspot names.
- **Your own leaks:** saved network names your phone broadcasts.
- **Weak networks:** open, WEP, WPS unlocked, TKIP, factory-default names.
- **People nearby:** iPhones from Apple Continuity adverts + other phones
  from probe requests clustered by IE fingerprint and sequence number,
  scaled by US smartphone ownership (91%, Pew 2025) and iOS share (58%).
  Shown as a range and a category.

- **SENSE (ambient motion radar):** every transmitter the Core2 hears is
  one end of a radio link. A body moving through a link changes its
  per-subcarrier CSI (or RSSI on links without CSI). Each link learns its
  quiet-room floor; motion lights that link, and motion on every link means
  something is moving at the Core2. Hold A for a one-turn bearing sweep, and
  disturbances then show as directions (somewhere between you and that
  transmitter). A arms SENTRY: buzz and log on any disturbance.

  *CSI build switch.* The driver produces CSI only if the core was built with
  `CONFIG_ESP32_WIFI_CSI_ENABLED` (IDF 4.x) / `CONFIG_ESP_WIFI_CSI_ENABLED`
  (IDF 5.x). ESP-IDF defaults it to off, but the Arduino-ESP32 2.0.x core that
  the default `m5stack-core2` env installs ships with it on, so the default
  build needs nothing extra. The optional `m5stack-core2-idf5` env (Arduino 3.x
  via pioarduino) forces it on with `custom_sdkconfig`. If a core lacks it,
  the build prints a `#warning`, SENSE skips the CSI calls and runs on RSSI.
  The status line shows what SENSE is using right now: `CSI`, `CSI WAIT` (armed,
  no OFDM traffic yet), `CSI MUTE` (armed but the driver sends nothing),
  or `RSSI`. The serial log prints every change.

**Radio schedule.** WiFi and BLE share one radio. Espressif's arbiter rates
sniffer + BLE scan as "supported, sniffer packet loss unstable", so the audit
schedules it instead: two clean 13-channel WiFi sweeps (about 5.7 s), then a
2 s passive BLE window. Each side's results stay cached between windows.
Fox hunts, CHALLENGE and SENSE hold the radio on one side.

**Can't see:** 5 GHz-only, wired (PoE), cellular and SD-card-only cameras;
glasses that stop advertising once paired.

**Views** (BtnB): SITREP · CAMERAS · TRACKERS · CROWD · SENSE · LEAKS ·
SPECTRUM · NETWORKS. **Tap a row for INTEL:** A = **FOX HUNT** (locks onto that one
transmitter: live dBm, warmer/colder, peak hold, rough distance, body-shadow
bearing arrow, Geiger clicks), B = CHALLENGE, hold B = mark friendly (saved to
`/friendly.txt`), hold A = classic radar.

Add your own prefixes on SD in `/intel_oui.txt` (`AABBCC,cam,Name`;
categories cam, lpr, pol, drone, veh, atk, iot). Rebuild the built-in table
with `tools/gen_intel.py`.

## Hardware

- M5Stack Core2 (ESP32, 320×240, IMU, touch)
- No external modules required

## Build locally

```bash
# PlatformIO
pio run -e m5stack-core2
pio run -e m5stack-core2 -t upload
```

Or open this folder in VS Code / Cursor with the PlatformIO extension.

## CI / drop-zip / web flasher

Same bootstrap pattern as the original Fox project:

| Workflow | Purpose |
|----------|---------|
| `drop_zip.yml` | Push a `*.zip` to the repo root → expands & commits |
| `build-firmware.yml` | PlatformIO build for Core2 → artifact + GitHub Pages |
| `pages.yml` | Redeploy web flasher without rebuilding firmware |

**First-time setup on a fresh repo:**

1. Keep only `.github/workflows/drop_zip.yml`.
2. Commit `DeviceRadar.zip` (this whole tree) to the **repo root**.
3. The drop_zip workflow expands it. Then move `github/workflows/*` into
   `.github/workflows/` (tokens cannot write workflow files from a zip).
4. Push to `main` → `build-firmware` builds, packages `dist/`, and deploys
   the web flasher to GitHub Pages.

The flasher lives at `web/index.html` and uses
[esp-web-tools](https://esphome.github.io/esp-web-tools/). After a successful
build the Install button pulls `firmware/manifest.json` + bins.

## Layout

```
core2_radar/
├── platformio.ini
├── src/
│   ├── main.cpp            # DeviceRadar firmware
│   └── mantis_sprite.h     # 24×24 RGB565 mascot for radar centre
├── assets/                 # source logo crops
├── web/
│   ├── index.html          # Mantis-themed web flasher
│   ├── mantis.png          # logo
│   ├── favicon-*.png
│   └── …
├── github/workflows/       # ship-in-zip copies (move to .github/)
└── .github/workflows/      # active CI
```

## Controls summary

| Screen | Action | Input |
|--------|--------|-------|
| Menu | Start an item | Tap it, or BtnA for the highlighted one |
| Menu | Next item | BtnB |
| Menu | Power off | Hold BtnC |
| Radar | Rescan | BtnA |
| Radar | Device list | BtnB |
| Radar | Device details | Tap a dot |
| Radar | Exit | BtnC (or hold BtnA) |
| List | Select / details | Tap a row / tap it again (or hold BtnA) |
| List | Move | BtnA up · BtnB down · swipe to page |
| List | Back | BtnC or tap `< back` |
| Details | Fox hunt this device (WiFi AP or BLE) | BtnA or tap `A HUNT` |
| Details | Back | BtnB, BtnC or tap anywhere else |
| Audit | Change view | BtnB |
| Audit | Intel | Tap a row |
| Audit | Fox hunt / challenge | BtnA / BtnB in Intel |
| Audit | Mark friendly | Hold BtnB in Intel |
| Audit | Reset / exit | BtnA / BtnC |

## License

Radar logic ported from the Fox project. This standalone DeviceRadar / Mantis
edition is provided as-is for personal and educational use.

## Screens

Rendered from the firmware's own draw code against a synthetic hotel-lobby
scene (the same frames the detector tests use), not mock-ups:
`docs/screens/screens_1_radar.png`, `screens_2_threat_audit.png`,
`screens_3_intel_sense.png`, `screens_4_fox_challenge.png`.
Fonts are approximated (Font0 is exact at 6 px per character).
