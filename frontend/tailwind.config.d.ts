declare const _default: {
    content: string[];
    theme: {
        extend: {
            colors: {
                aegis: {
                    bg: string;
                    panel: string;
                    panel2: string;
                    cyan: string;
                    pink: string;
                    purple: string;
                    lime: string;
                    danger: string;
                    warn: string;
                };
            };
            boxShadow: {
                neon: string;
                magenta: string;
            };
            keyframes: {
                pulseGlow: {
                    "0%, 100%": {
                        opacity: string;
                        transform: string;
                    };
                    "50%": {
                        opacity: string;
                        transform: string;
                    };
                };
                scanline: {
                    "0%": {
                        transform: string;
                    };
                    "100%": {
                        transform: string;
                    };
                };
                flicker: {
                    "0%, 100%": {
                        opacity: string;
                    };
                    "50%": {
                        opacity: string;
                    };
                };
            };
            animation: {
                pulseGlow: string;
                scanline: string;
                flicker: string;
            };
        };
    };
    plugins: any[];
};
export default _default;
