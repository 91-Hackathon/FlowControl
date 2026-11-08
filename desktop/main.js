/* FlowControl desktop: a window around ../dashboard, unchanged.

   npm start                 live: connects to ws://localhost:8080/events (retries every 2s)
   npm run demo              demo replay, no gateway needed
   npm start -- --ws=ws://host:port/events   another gateway
   FC_WS=ws://...            same, from the environment

   The dashboard files are loaded as they are (in development straight from ../dashboard,
   in a packaged app from the copy bundled into resources/). Fonts are bundled too, so the
   app looks identical offline. */
const { app, BrowserWindow, Menu, shell, session, nativeTheme } = require("electron");
app.setName("FlowControl"); // menu items (About / Hide / Quit FlowControl), window title, data folder
const path = require("path");
const fs = require("fs");
const { pathToFileURL } = require("url");

const packaged = app.isPackaged;
const DASHBOARD = packaged ? path.join(process.resourcesPath, "dashboard") : path.join(__dirname, "..", "dashboard");
const FONTS = packaged
  ? { inter: path.join(process.resourcesPath, "fonts", "inter"), plex: path.join(process.resourcesPath, "fonts", "plex") }
  : { inter: path.join(__dirname, "node_modules/@fontsource/inter/files"), plex: path.join(__dirname, "node_modules/@fontsource/ibm-plex-mono/files") };

const argv = process.argv.slice(1);
const wsArg = (argv.find((a) => a.startsWith("--ws=")) || "").slice(5) || process.env.FC_WS || "";
let mode = argv.includes("--demo") ? "demo" : "live";
let win;

/* Same families the page asks Google Fonts for, served from local files. */
function fontCSS() {
  const face = (family, dir, file, weight) => {
    const p = path.join(dir, file);
    if (!fs.existsSync(p)) return "";
    return `@font-face{font-family:"${family}";font-style:normal;font-weight:${weight};font-display:block;src:url("${pathToFileURL(p).href}") format("woff2");}`;
  };
  return [400, 500, 600, 700, 800].map((w) => face("Inter", FONTS.inter, `inter-latin-${w}-normal.woff2`, w)).join("") +
    [400, 500].map((w) => face("IBM Plex Mono", FONTS.plex, `ibm-plex-mono-latin-${w}-normal.woff2`, w)).join("");
}

/* The header doubles as the title bar: drag the window by it, leave room for the window
   controls (traffic lights on the left on macOS, min/max/close on the right elsewhere). */
const HEADER_H = 62;
function chromeCSS() {
  const room = process.platform === "darwin" ? ".top{padding-left:88px !important}" : ".top{padding-right:150px !important}";
  return `.top{-webkit-app-region:drag;min-height:${HEADER_H}px;-webkit-user-select:none}` +
    `.top button,.top a,.top input,.top .conn{-webkit-app-region:no-drag}` + room;
}

function load() {
  const query = {};
  if (mode === "demo") query.demo = "";
  if (wsArg && mode === "live") query.ws = wsArg;
  const search = Object.entries(query).map(([k, v]) => (v ? `${k}=${encodeURIComponent(v)}` : k)).join("&");
  win.loadFile(path.join(DASHBOARD, "index.html"), search ? { search } : {});
  buildMenu();
}

// Packaged builds get the icon from electron-builder (build/icon.*). In development, set it here.
const DEV_ICON = path.join(__dirname, "build", "icon.png");

function createWindow() {
  win = new BrowserWindow({
    ...(!packaged && process.platform !== "darwin" ? { icon: DEV_ICON } : {}),
    width: 1440, height: 900, minWidth: 960, minHeight: 600,
    title: "FlowControl",
    backgroundColor: "#ffffff",
    // No native title bar: the window controls sit inside the dashboard's own white header.
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "hidden",
    trafficLightPosition: { x: 16, y: 24 },
    ...(process.platform === "darwin" ? {} : { titleBarOverlay: { color: "#ffffff", symbolColor: "#111111", height: HEADER_H } }),
    show: false,
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.once("ready-to-show", () => win.show());
  // FC_CAPTURE=out.png [FC_CAPTURE_AFTER=ms]: save a screenshot of the window, then quit (for checks/CI).
  if (process.env.FC_CAPTURE) {
    win.webContents.once("did-finish-load", () => setTimeout(async () => {
      fs.writeFileSync(process.env.FC_CAPTURE, (await win.webContents.capturePage()).toPNG());
      const fonts = await win.webContents.executeJavaScript(
        `document.fonts.ready.then(() => [document.fonts.check('16px Inter'), document.fonts.check('12px "IBM Plex Mono"'), getComputedStyle(document.body).fontFamily])`);
      console.log("captured", process.env.FC_CAPTURE, JSON.stringify(fonts));
      app.quit();
    }, Number(process.env.FC_CAPTURE_AFTER || 12000)));
  }
  win.webContents.on("dom-ready", () => win.webContents.insertCSS(fontCSS() + chromeCSS()));

  // Stay inside the dashboard: in-page links (like the "demo" link) reload it, anything else opens in the browser.
  win.webContents.on("will-navigate", (e, url) => {
    if (url.startsWith("file:")) {
      e.preventDefault();
      mode = /[?&]demo\b/.test(url) ? "demo" : "live";
      load();
      return;
    }
    e.preventDefault();
    if (/^https?:/.test(url)) shell.openExternal(url);
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  load();
}

function buildMenu() {
  const isMac = process.platform === "darwin";
  const template = [
    ...(isMac ? [{ role: "appMenu" }] : []),
    {
      label: "Run",
      submenu: [
        { label: "Live gateway", type: "radio", checked: mode === "live", accelerator: "CmdOrCtrl+1", click: () => { mode = "live"; load(); } },
        { label: "Demo replay", type: "radio", checked: mode === "demo", accelerator: "CmdOrCtrl+2", click: () => { mode = "demo"; load(); } },
        { type: "separator" },
        ...(isMac ? [] : [{ role: "quit" }]),
      ],
    },
    { role: "editMenu" },
    {
      label: "View",
      submenu: [
        { role: "reload" }, { role: "forceReload" }, { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    { role: "windowMenu" },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(() => {
  nativeTheme.themeSource = "light"; // the dashboard is light only; keep dialogs and menus matching
  if (!packaged && process.platform === "darwin" && app.dock && fs.existsSync(DEV_ICON)) app.dock.setIcon(DEV_ICON);
  // Fonts come from the bundle; don't wait on Google Fonts (it may be unreachable offline).
  session.defaultSession.webRequest.onBeforeRequest({ urls: ["https://fonts.googleapis.com/*", "https://fonts.gstatic.com/*"] }, (_d, cb) => cb({ cancel: true }));
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
