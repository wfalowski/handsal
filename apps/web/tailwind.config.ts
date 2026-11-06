import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        display: ['"Space Grotesk"', "Inter", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      colors: {
        accent: { DEFAULT: "#3B5BDB", hover: "#2F4AB8" },
        surface: "#F6F6F7",
        hover: "#F1F1F3",
        line: { DEFAULT: "#E4E4E7", strong: "#D4D4D8" },
        faint: "#A1A1AA",
        muted: "#6B6B76",
        body: "#3F3F46",
        ink: "#09090B",
        success: { DEFAULT: "#15803D", bg: "#ECFDF3" },
        warning: { DEFAULT: "#B45309", bg: "#FEF3C7" },
        danger: { DEFAULT: "#B91C1C", bg: "#FEF2F2" },
        info: { DEFAULT: "#3730A3", bg: "#EEF1FF" },
      },
    },
  },
  plugins: [],
};

export default config;
