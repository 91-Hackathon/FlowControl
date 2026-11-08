/* Development only (macOS): `npm start` runs Electron's own Electron.app, so the menu bar and
   Dock say "Electron". Rename that bundle's display name to FlowControl. Packaged builds don't
   need this: electron-builder writes productName into their Info.plist. Safe to run repeatedly. */
const fs = require("fs");
const path = require("path");

if (process.platform !== "darwin") process.exit(0);
const NAME = require("../package.json").productName || "FlowControl";
const app = path.join(__dirname, "..", "node_modules", "electron", "dist", "Electron.app");
const plist = path.join(app, "Contents", "Info.plist");
if (!fs.existsSync(plist)) process.exit(0);

const before = fs.readFileSync(plist, "utf8");
const after = before.replace(/(<key>CFBundle(?:Display)?Name<\/key>\s*<string>)[^<]*(<\/string>)/g, `$1${NAME}$2`);
if (after !== before) {
  fs.writeFileSync(plist, after);
  const now = new Date();
  fs.utimesSync(app, now, now); // nudge macOS to re-read the bundle's name
  console.log(`dev app name set to ${NAME}`);
}
