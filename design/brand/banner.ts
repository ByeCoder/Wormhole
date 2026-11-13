// The art of assets/banner.png and assets/social-preview.png: the panel's own space and
// planet, drawn by the panel's own scenes. Built into banner.js with:
//   esbuild design/brand/banner.ts --bundle --minify --outfile=design/brand/banner.js
import { startCosmos } from "../../panel/web/src/scene-cosmos";
import { startMap } from "../../panel/web/src/scene-planet";
import type { MapData } from "../../panel/web/src/scene-planet";
import { readPalette } from "../../panel/web/src/draw";

const data: MapData = {
  servers: [
    { id: "teh", name: "Tehran", sub: "", st: "up", place: "tehran" },
    { id: "fra", name: "Frankfurt", sub: "", st: "up", place: "frankfurt" },
    { id: "ams", name: "Amsterdam", sub: "", st: "up", place: "amsterdam" },
    { id: "hel", name: "Helsinki", sub: "", st: "up", place: "helsinki" },
    { id: "ist", name: "Istanbul", sub: "", st: "up", place: "istanbul" },
  ],
  tunnels: [
    { id: "a", a: "teh", b: "fra", st: "up", rate: 640, label: "main", value: "640 Mbps" },
    { id: "b", a: "teh", b: "ams", st: "up", rate: 310, label: "cdn", value: "310 Mbps" },
    { id: "c", a: "teh", b: "hel", st: "up", rate: 180, label: "games", value: "180 Mbps" },
    { id: "d", a: "teh", b: "ist", st: "up", rate: 120, label: "backup", value: "120 Mbps" },
  ],
};

startCosmos(document.getElementById("cosmos") as HTMLCanvasElement);
const palette = readPalette();
startMap(document.getElementById("planet") as HTMLCanvasElement, {
  data: () => data,
  palette: () => palette,
  low: () => false,
  rtl: () => false,
  onHover: () => {},
  onOpen: () => {},
});
