# FlowControl desktop

The FlowControl dashboard in its own window, for macOS, Windows and Linux (Electron).
It loads `../dashboard` exactly as it is, so the design is identical to the browser
version, and any change to the dashboard shows up here too. Inter and IBM Plex Mono are
bundled, so it looks the same offline.

## Run (development)

```bash
cd desktop
npm install
npm start            # live: connects to the gateway at ws://localhost:8080/events
npm run demo         # demo replay, no gateway needed
npm start -- --ws=ws://host:9000/events   # another gateway (or set FC_WS)
```

Menu **Run → Live gateway (⌘1) / Demo replay (⌘2)** switches between the two.
**View → Toggle Developer Tools** opens the inspector. **P** is presenter mode, as in the browser.

## Build installers

```bash
npm run dist:mac     # dist/*.dmg, *.zip
npm run dist:win     # dist/*.exe (installer + portable)
npm run dist:linux   # dist/*.AppImage, *.deb
```

Each build copies `../dashboard` and the fonts into the app's resources. Builds are not
code-signed: macOS asks you to right-click → Open the first time, and Windows SmartScreen
shows "More info → Run anyway". Building for Windows or Linux works best on that platform
(or in CI); cross-building from a Mac may need extra tools.

## Files

| File | Job |
|---|---|
| `main.js` | Window, menu, live/demo switch, bundled fonts, keeps navigation inside the dashboard |
| `scripts/dev-name.js` | macOS, development only: renames the bundled Electron.app to FlowControl so the menu bar and Dock show it (runs on install and before `npm start`) |
| `build/icon.svg` | The app icon (source). `icon.icns` (macOS), `icon.ico` (Windows) and `icon.png` (Linux, dev Dock) are rendered from it |
| `preload.js` | Empty on purpose: the page gets no Node access, it runs as in a browser |
| `package.json` | Scripts and electron-builder settings (what goes into the installers) |

For checks: `FC_CAPTURE=out.png npm run demo` saves a screenshot of the window after 12s
(`FC_CAPTURE_AFTER=ms` to change) and quits.

To change the icon, edit `build/icon.svg` and re-render (needs `rsvg-convert` and ImageMagick):

```bash
cd desktop/build && mkdir -p icon.iconset && for s in 16 32 128 256 512; do rsvg-convert -w $s -h $s icon.svg -o icon.iconset/icon_${s}x${s}.png; rsvg-convert -w $((s*2)) -h $((s*2)) icon.svg -o icon.iconset/icon_${s}x${s}@2x.png; done && iconutil -c icns icon.iconset -o icon.icns && rsvg-convert -w 1024 -h 1024 icon.svg -o icon.png && magick icon.iconset/icon_16x16.png icon.iconset/icon_32x32.png icon.iconset/icon_128x128.png icon.iconset/icon_256x256.png icon.ico && rm -rf icon.iconset
```
