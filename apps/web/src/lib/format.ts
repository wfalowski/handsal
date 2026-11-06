const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];
const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

export function relativeTime(iso: string): string {
  const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  for (const [unit, size] of UNITS) {
    if (abs >= size) return rtf.format(Math.trunc(seconds / size), unit);
  }
  return seconds > 0 ? "in <1 min" : "just now";
}

export function compactNumber(n: number): string {
  if (n < 1000) return String(n);
  const [div, suffix] = n >= 1_000_000 ? [1_000_000, "M"] : [1000, "k"];
  return `${(Math.floor((n / div) * 10) / 10).toFixed(1).replace(/\.0$/, "")}${suffix}`;
}

export function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  const first = words[0] ?? "";
  const letters = words.length > 1 ? `${first[0]}${words[1]?.[0]}` : first.slice(0, 2);
  return letters.toUpperCase();
}

export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/, "");
}

const TINTS = [
  { tint: "#E0E7FF", ink: "#3730A3" },
  { tint: "#DCFCE7", ink: "#166534" },
  { tint: "#FEF3C7", ink: "#92400E" },
  { tint: "#FCE7F3", ink: "#9D174D" },
  { tint: "#F1F1F3", ink: "#3F3F46" },
];

/** Deterministic tile colours from the slug. */
export function tenantTint(slug: string): { tint: string; ink: string } {
  let h = 0;
  for (const ch of slug) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return TINTS[h % TINTS.length] as { tint: string; ink: string };
}
