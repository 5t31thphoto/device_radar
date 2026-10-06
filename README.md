# DeviceRadar — Mantis Edition

Standalone **WiFi + BLE rotational radar** for **M5Stack Core2**, using **M5Unified**.

Ported from the Fox Voice Companion radar tools. Single merged binary with an
on-device menu. The pixel mantis is the mascot: it sits in the centre of every
radar sweep, owns the splash screen, and is the favicon of the web flasher.

**Theme:** `#007373` teal · `#5d005d` purple · lime green · dark grey

---

## What it does

1. Choose **WiFi Radar** or **BLE Radar** from the menu.
2. Hold still for gyro bias calibration.
3. Slowly turn in place (~20 s full circle). Keep the **green** needle on the
   **red** target. Scans run in the background.
4. After one full turn the map is live — devices plotted by estimated bearing;
   radius is relative RSSI only (not metres).
5. **BtnA** / touch = rescan · **BtnC** = exit.

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

| Action | Input |
|--------|--------|
| Select / confirm | BtnA or touch (upper) |
| Next menu item | BtnB |
| Rescan (live) | BtnA or touch |
| Exit radar | BtnC |
| Power off | Long-press BtnC (menu) |

## License

Radar logic ported from the Fox project. This standalone DeviceRadar / Mantis
edition is provided as-is for personal and educational use.
