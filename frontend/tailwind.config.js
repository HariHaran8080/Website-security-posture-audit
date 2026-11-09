/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: "#0F1720",
        paper: "#F7F6F2",
        surface: "#FFFFFF",
        line: "#E3E0D8",
        muted: "#3A4552",
        subtle: "#5B6470",
        accent: "#F5B301",
        // Severity primary colors
        critical: "#9B1C13",
        high: "#D9631A",
        medium: "#E8B923",
        low: "#6FA48A",
        // Chip background and text pairs
        chip: {
          critical: {
            bg: "#FDE8E6",
            text: "#8E1B12",
          },
          high: {
            bg: "#FDEBDD",
            text: "#8F3A0A",
          },
          medium: {
            bg: "#FBF1CC",
            text: "#6B4E00",
          },
          low: {
            bg: "#E4EEE9",
            text: "#1F5A3D",
          },
        },
      },
      fontFamily: {
        heading: ['"Space Grotesk"', 'sans-serif'],
        sans: ['Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      maxWidth: {
        content: "1200px",
      },
    },
  },
  plugins: [],
}

