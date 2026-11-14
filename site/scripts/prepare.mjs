// Copies what the site shares with the rest of the repository into places Astro can serve:
// the panel's tokens and fonts, and the interactive prototype (the live demo). Nothing here
// is committed; the repository has one copy of each.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repo = path.resolve(site, "..");
const rm = (p) => fs.rmSync(p, { recursive: true, force: true });
const cp = (a, b) => fs.cpSync(a, b, { recursive: true });

// Tokens and fonts for the site's own styles.
const panel = path.join(site, "src/styles/panel");
rm(panel);
fs.mkdirSync(panel, { recursive: true });
cp(path.join(repo, "panel/web/src/tokens.css"), path.join(panel, "tokens.css"));
cp(path.join(repo, "panel/web/src/fonts"), path.join(panel, "fonts"));

// The panel's drawing helpers, which the hero scene shares with the panel's own scenes.
const scripts = path.join(site, "src/scripts/panel");
rm(scripts);
fs.mkdirSync(scripts, { recursive: true });
cp(path.join(repo, "panel/web/src/draw.ts"), path.join(scripts, "draw.ts"));

cp(path.join(repo, "assets/logo.svg"), path.join(site, "public/logo.svg"));
// The tab icon: a simpler drawing of the logo that stays readable at 16 pixels.
for (const icon of ["favicon.svg", "favicon.ico", "favicon-32.png", "apple-touch-icon.png"]) {
  cp(path.join(repo, "assets", icon), path.join(site, "public", icon));
}
// The pictures the docs show (the donation QR codes): the docs link to docs/images/, the site serves a copy.
const images = path.join(site, "public/docs-images");
rm(images);
cp(path.join(repo, "docs/images"), images);
// The card that link previews show (the repository's social image).
cp(path.join(repo, "assets/social-preview.png"), path.join(site, "public/social-preview.png"));
console.log("site assets ready");
