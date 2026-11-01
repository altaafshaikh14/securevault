/** Build: npx tailwindcss@3.4.16 -c tailwind.config.js -i tailwind.input.css -o public/securevault.css --minify */
module.exports = {
    content: ['./public/index.html', './public/securevault.js'],
    darkMode: 'class',
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                mono: ['"JetBrains Mono"', 'monospace'],
            },
            colors: {
                slate: {
                    850: '#131b2e',
                    950: '#070a12'
                },
                // "Midnight Trust" palette: blue = primary/trust, emerald = secured/success, amber = caution,
                // rose = danger, sky = info, purple = secondary tools. Text shades 300/400 pass WCAG AA on slate-900.
                indigo: {
                    50: '#eef2fd', 100: '#dde5fb', 200: '#bfcdf7', 300: '#9db1f2', 400: '#7c95ea',
                    500: '#4866d1', 600: '#3a53b3', 700: '#304491', 800: '#283872', 900: '#1f2b56', 950: '#141c38'
                },
                purple: {
                    50: '#f5f1fc', 100: '#ebe2f8', 200: '#d8c7f2', 300: '#c2acee', 400: '#a88be2',
                    500: '#8a68cf', 600: '#7151b1', 700: '#5b4290', 800: '#473471', 900: '#352855', 950: '#231a38'
                },
                emerald: {
                    50: '#ecf9f3', 100: '#d4f2e5', 200: '#a9e5cc', 300: '#7fd6b5', 400: '#4cc49a',
                    500: '#2fa47c', 600: '#258565', 700: '#1f6a51', 800: '#195340', 900: '#143f31', 950: '#0c2920'
                },
                sky: {
                    50: '#ecf6fc', 100: '#d6ebf8', 200: '#b0d9f2', 300: '#8ecbee', 400: '#5fb0e2',
                    500: '#3b91c6', 600: '#2f75a2', 700: '#285e82', 800: '#214a66', 900: '#1a384d', 950: '#112532'
                },
                rose: {
                    50: '#fdf0f2', 100: '#fadfe3', 200: '#f5c1c9', 300: '#f2a1ad', 400: '#e87888',
                    500: '#c64a5e', 600: '#ad3f51', 700: '#8b3342', 800: '#6c2834', 900: '#501e27', 950: '#341419'
                },
                amber: {
                    50: '#fdf6e9', 100: '#fbecce', 200: '#f6da9f', 300: '#f2c977', 400: '#e8ad48',
                    500: '#cc902d', 600: '#a67425', 700: '#835c1f', 800: '#65471a', 900: '#4b3515', 950: '#30220d'
                }
            }
        }
    }
};
