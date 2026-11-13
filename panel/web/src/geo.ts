// Where on the planet a server stands, and where the land is.
//
// A server is placed by the city (or country) its name or host name mentions, in English
// or Persian ("Frankfurt · Hetzner", "fra-1", "تهران"). A name with no place in it gets a
// steady spot of its own (from a hash of its id), so it never jumps between reloads.
// The continents are a rough outline, enough to make the planet read as ours.

/** [words, latitude, longitude]. Words are matched whole, case-insensitive. */
const PLACES: [string[], number, number][] = [
  [["tehran", "thr", "teh", "تهران"], 35.7, 51.4],
  [["mashhad", "مشهد"], 36.3, 59.6],
  [["isfahan", "esfahan", "اصفهان"], 32.7, 51.7],
  [["tabriz", "تبریز"], 38.1, 46.3],
  [["shiraz", "شیراز"], 29.6, 52.5],
  [["karaj", "کرج"], 35.8, 51.0],
  [["iran", "ir", "ایران", "asiatech", "mci", "irancell", "shatel", "mokhaberat", "afranet", "parsonline", "arvan", "ابر", "آروان"], 33.5, 53.5],
  [["frankfurt", "fra", "فرانکفورت"], 50.1, 8.7],
  [["nuremberg", "nbg", "falkenstein", "fsn", "نورنبرگ"], 49.5, 11.1],
  [["berlin", "برلین"], 52.5, 13.4],
  [["germany", "de", "hetzner", "آلمان"], 51.0, 10.0],
  [["helsinki", "hel", "هلسینکی"], 60.2, 24.9],
  [["finland", "fi", "فنلاند"], 61.9, 25.7],
  [["amsterdam", "ams", "آمستردام"], 52.4, 4.9],
  [["netherlands", "nl", "holland", "leaseweb", "هلند"], 52.1, 5.3],
  [["london", "lon", "lhr", "لندن"], 51.5, -0.1],
  [["uk", "gb", "england", "انگلیس", "انگلستان"], 52.5, -1.5],
  [["paris", "par", "پاریس"], 48.9, 2.35],
  [["france", "fr", "ovh", "فرانسه"], 46.6, 2.2],
  [["stockholm", "sto", "sweden", "سوئد"], 59.3, 18.1],
  [["warsaw", "waw", "poland", "pl", "لهستان"], 52.2, 21.0],
  [["vienna", "vie", "austria", "اتریش"], 48.2, 16.4],
  [["zurich", "zrh", "switzerland", "ch", "سوئیس"], 47.4, 8.5],
  [["milan", "mil", "italy", "ایتالیا"], 45.5, 9.2],
  [["madrid", "mad", "spain", "اسپانیا"], 40.4, -3.7],
  [["istanbul", "ist", "استانبول"], 41.0, 29.0],
  [["turkey", "tr", "türkiye", "ترکیه"], 39.0, 35.0],
  [["moscow", "mow", "مسکو"], 55.8, 37.6],
  [["russia", "ru", "روسیه"], 56.0, 45.0],
  [["kyiv", "kiev", "ukraine", "ua", "اوکراین"], 50.4, 30.5],
  [["yerevan", "armenia", "ارمنستان", "ایروان"], 40.2, 44.5],
  [["baku", "azerbaijan", "az", "باکو", "آذربایجان"], 40.4, 49.9],
  [["tbilisi", "georgia", "ge", "گرجستان", "تفلیس"], 41.7, 44.8],
  [["dubai", "dxb", "uae", "ae", "دبی", "امارات"], 25.2, 55.3],
  [["doha", "qatar", "qa", "قطر"], 25.3, 51.5],
  [["riyadh", "saudi", "عربستان"], 24.7, 46.7],
  [["bahrain", "bh", "بحرین"], 26.1, 50.6],
  [["oman", "muscat", "عمان"], 23.6, 58.4],
  [["mumbai", "bom", "india", "هند"], 19.1, 72.9],
  [["singapore", "sin", "sg", "سنگاپور"], 1.35, 103.8],
  [["hong", "hkg", "hk", "هنگ‌کنگ"], 22.3, 114.2],
  [["tokyo", "tyo", "nrt", "japan", "jp", "ژاپن", "توکیو"], 35.7, 139.7],
  [["seoul", "icn", "korea", "kr", "کره"], 37.6, 127.0],
  [["sydney", "syd", "australia", "au", "استرالیا"], -33.9, 151.2],
  [["toronto", "yyz", "canada", "ca", "کانادا"], 43.7, -79.4],
  [["montreal", "bhs", "yul"], 45.5, -73.6],
  [["new york", "nyc", "jfk", "newyork", "نیویورک"], 40.7, -74.0],
  [["ashburn", "iad", "virginia", "واشنگتن"], 39.0, -77.5],
  [["chicago", "ord", "شیکاگو"], 41.9, -87.6],
  [["dallas", "dfw"], 32.8, -96.8],
  [["miami", "mia", "میامی"], 25.8, -80.2],
  [["los angeles", "lax", "لس‌آنجلس"], 34.1, -118.2],
  [["seattle", "sea"], 47.6, -122.3],
  [["san jose", "sjc", "silicon", "sanfrancisco", "sfo"], 37.4, -121.9],
  [["usa", "us", "america", "آمریکا"], 39.5, -98.0],
  [["sao paulo", "gru", "brazil", "br", "برزیل"], -23.5, -46.6],
  [["johannesburg", "jnb", "africa", "za", "آفریقا"], -26.2, 28.0],
];

const hash = (text: string) => {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619);
  return h >>> 0;
};

/** Latitude and longitude, in degrees, for a server. */
export function placeOf(id: string, text: string): [number, number] {
  const words = text
    .toLowerCase()
    .replace(/[·|,()[\]_.]/g, " ")
    .split(/[\s]+/)
    .flatMap((w) => [w, ...w.split("-")])
    .filter(Boolean);
  const joined = ` ${words.join(" ")} `;
  // Cities come before countries in the table, so the most precise word wins.
  for (const [names, lat, lon] of PLACES) {
    if (names.some((n) => (n.includes(" ") ? joined.includes(` ${n} `) : words.includes(n)))) {
      // Two servers in one city stand a little apart.
      const h = hash(id);
      return [lat + ((h % 100) / 100 - 0.5) * 3, lon + (((h >> 8) % 100) / 100 - 0.5) * 4];
    }
  }
  const h = hash(id);
  return [-35 + (h % 1000) * 0.09, -170 + ((h >> 10) % 3400) * 0.1];
}

/** Rough outlines of the land, as [longitude, latitude] rings. */
const LAND: [number, number][][] = [
  // North America
  [[-168, 66], [-140, 70], [-110, 72], [-80, 73], [-62, 60], [-55, 50], [-66, 45], [-75, 35], [-80, 26], [-82, 30], [-90, 29], [-97, 26], [-97, 20], [-88, 21], [-84, 15], [-79, 9], [-83, 8], [-92, 14], [-105, 20], [-112, 30], [-117, 33], [-124, 40], [-124, 48], [-135, 58], [-150, 60], [-165, 60]],
  // Greenland
  [[-50, 60], [-40, 62], [-22, 70], [-20, 80], [-40, 83], [-60, 80], [-70, 77], [-55, 70]],
  // South America
  [[-80, 9], [-72, 12], [-60, 10], [-50, 0], [-35, -6], [-39, -14], [-41, -22], [-48, -26], [-58, -34], [-62, -40], [-66, -46], [-69, -52], [-74, -52], [-74, -42], [-71, -30], [-70, -18], [-76, -14], [-81, -5], [-80, 1]],
  // Europe
  [[-10, 36], [-9, 43], [-2, 44], [-4, 48], [2, 51], [8, 54], [10, 57], [5, 58], [6, 62], [14, 67], [24, 71], [30, 70], [40, 67], [45, 68], [60, 69], [60, 55], [50, 47], [40, 45], [30, 46], [28, 41], [26, 38], [22, 37], [20, 40], [15, 38], [12, 44], [8, 44], [3, 43], [-5, 36]],
  // Britain
  [[-5, 50], [1, 51], [-1, 55], [-3, 58], [-6, 57], [-3, 54]],
  // Asia
  [[26, 41], [36, 36], [44, 38], [48, 30], [56, 27], [62, 25], [67, 25], [72, 21], [77, 8], [80, 15], [88, 22], [92, 21], [97, 16], [98, 8], [104, 1], [100, 13], [106, 10], [109, 19], [110, 21], [122, 25], [122, 31], [121, 38], [129, 35], [127, 40], [135, 43], [142, 47], [143, 54], [155, 58], [160, 60], [175, 62], [180, 66], [170, 70], [150, 71], [130, 72], [110, 77], [90, 76], [70, 73], [60, 69], [60, 55], [50, 47], [40, 45], [30, 46]],
  // Arabia
  [[35, 29], [39, 22], [43, 13], [50, 15], [57, 20], [59, 23], [56, 26], [51, 24], [48, 29]],
  // Africa
  [[-17, 15], [-17, 21], [-13, 28], [-6, 35], [10, 37], [20, 32], [32, 31], [35, 28], [43, 12], [51, 12], [42, -2], [40, -11], [35, -24], [32, -29], [20, -35], [17, -29], [12, -17], [13, -6], [9, -1], [9, 4], [3, 6], [-8, 4], [-13, 8]],
  // Madagascar
  [[44, -16], [50, -15], [47, -25], [44, -23]],
  // Australia
  [[114, -22], [122, -18], [130, -12], [137, -12], [142, -11], [146, -19], [153, -26], [150, -37], [140, -38], [132, -32], [115, -34]],
  // Japan
  [[130, 31], [136, 34], [141, 38], [142, 45], [140, 41], [135, 35]],
  // Sumatra, Java and the islands east of them
  [[95, 5], [105, -6], [115, -8], [120, -9], [125, -8], [117, -2], [110, -2], [102, 1]],
  // Borneo
  [[109, 2], [117, 7], [119, 1], [116, -4], [110, -3]],
];

function inside(ring: [number, number][], lon: number, lat: number): boolean {
  let hit = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i];
    const [xj, yj] = ring[j];
    if (yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}

/** Whether a point (degrees) is on land. */
export function isLand(lat: number, lon: number): boolean {
  if (lat < -68) return true;
  return LAND.some((ring) => inside(ring, lon, lat));
}
