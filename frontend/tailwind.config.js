/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Outfit", "system-ui", "sans-serif"],
      },
      colors: {
        dark: {
          bg: "#0A0D14",
          card: "#111622",
          border: "#1E2638",
          input: "#161D2E",
          hover: "#1B233A",
          text: "#F3F4F6",
        },
        cyber: {
          primary: "#3B82F6",
          accent: "#06B6D4",
          success: "#10B981",
          warning: "#F59E0B",
          danger: "#EF4444",
        }
      }
    },
  },
  plugins: [],
}
