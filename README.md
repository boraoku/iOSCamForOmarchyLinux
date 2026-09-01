# iOSCam for Omarchy

Use the **back camera of an iPhone** as a webcam on [Omarchy](https://omarchy.org/) Linux — the same idea as Continuity Camera on a Mac.

The phone is the lens. Linux apps see a normal camera named **iPhone Camera**. No App Store app: scan a QR code, trust a profile once, and Safari streams the back camera.

This is **not** Apple’s Continuity Camera protocol (that needs an Apple ID, AWDL, and a Mac). It is the closest thing that works on Linux.

![Omarchy](https://img.shields.io/badge/Omarchy-4-black) ![License](https://img.shields.io/badge/license-MIT-blue)

## Install

```sh
omarchy plugin add https://github.com/boraoku/iOSCamForOmarchyLinux.git --enable
```

Then create the virtual webcam (password once):

```sh
~/.config/omarchy/plugins/io.github.boraoku.ioscam/setup
```

That installs any missing packages (`ffmpeg`, `v4l2loopback`, …), starts a user service, and adds a V4L2 loopback device labelled **iPhone Camera**.

Move the bar icon if you want:

```sh
omarchy bar move io.github.boraoku.ioscam --section right
```

## Use it

1. Click the camera icon in the Omarchy bar and turn it on.
2. Scan the QR code with the iPhone (same Wi-Fi, or USB Personal Hotspot).
3. **First time only**
   - Tap **Install trust profile**
   - On the iPhone: **Settings → General → About → Certificate Trust Settings** → enable **Omarchy iPhone Camera**
   - Safari will not give the page the camera until that root is trusted
4. Tap **Open camera**, allow camera access, tap **Start back camera**.
5. Keep Safari in the foreground and the phone unlocked.
6. In Zoom, Google Meet, OBS, Discord, Chromium, or Firefox pick **iPhone Camera**.

### Bar shortcuts

| Input | Action |
| --- | --- |
| Left click | Open / close the panel |
| Right click | Start / stop the daemon |
| Middle click | Refresh |
| `c` | Copy the pairing link |
| `n` | New pairing code |
| `s` | Set up the virtual camera |
| Esc | Close |

## How it works

- A small Python daemon (stdlib only) serves an HTTP pairing page (`:4747`) and an HTTPS capture page (`:4748`).
- Safari captures the **back** camera and sends 1280×720 JPEG frames over a WebSocket.
- The daemon repeats the latest frame at a steady 24 fps into `ffmpeg`, which writes a constant-size YUV stream to a `v4l2loopback` device.
- Pairing URLs carry a secret token. **New code** in the panel invalidates the old QR.

Wired mode: plug the iPhone in, enable **Personal Hotspot → USB**, then scan again. Wi-Fi, USB-tether, and Tailscale addresses are all advertised.

## Requirements

- Omarchy 4 (Quickshell bar)
- iPhone with Safari (iOS 15+)
- `ffmpeg`, `openssl`, `qrencode`, `v4l2loopback-dkms`, `v4l2loopback-utils`
- Optional: `libimobiledevice` (ships with Omarchy) so the panel can notice a USB-connected iPhone

## What it does not do

- Capture while the iPhone is locked (Safari cannot keep the camera in the background)
- Center Stage, Studio Light, or Desk View (those are Apple-only)
- A native iOS app — on purpose, so nothing has to come from the App Store

## Remove

```sh
~/.config/omarchy/plugins/io.github.boraoku.ioscam/setup --uninstall
omarchy plugin remove io.github.boraoku.ioscam
```

## License

MIT. See [LICENSE](LICENSE).
