export default {
    content: ["./index.html", "./src/**/*.{ts,tsx}"],
    theme: {
        extend: {
            colors: {
                aegis: {
                    bg: "#06070d",
                    panel: "#0e1224",
                    panel2: "#131936",
                    cyan: "#27f5ff",
                    pink: "#ff2fbf",
                    purple: "#8e4dff",
                    lime: "#8bff3a",
                    danger: "#ff4d6d",
                    warn: "#ffb020",
                },
            },
            boxShadow: {
                neon: "0 0 18px rgba(39,245,255,0.35)",
                magenta: "0 0 18px rgba(255,47,191,0.35)",
            },
            keyframes: {
                pulseGlow: {
                    "0%, 100%": { opacity: "0.5", transform: "scale(1)" },
                    "50%": { opacity: "1", transform: "scale(1.02)" },
                },
                scanline: {
                    "0%": { transform: "translateY(-120%)" },
                    "100%": { transform: "translateY(120%)" },
                },
                flicker: {
                    "0%, 100%": { opacity: "1" },
                    "50%": { opacity: "0.82" },
                },
            },
            animation: {
                pulseGlow: "pulseGlow 2.4s ease-in-out infinite",
                scanline: "scanline 6s linear infinite",
                flicker: "flicker 3s linear infinite",
            },
        },
    },
    plugins: [],
};
