/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50:  '#f0f4ff',
          400: '#6b82f8',
          500: '#4f6ef7',
          600: '#3b55e6',
          700: '#2d44cc',
          800: '#1e337a',
          900: '#1a2a8a',
        },
        // User accent colours
        'accent-red': '#e8003d',
        'navy-deep':  '#000d40',
        'navy-light': '#1a3a8a',
        danger: {
          50:  '#fff1f0',
          500: '#ff4d4f',
          600: '#e63946',
        },
        success: { 500: '#22c55e' },
        warning: { 500: '#eab308' },
      },
      boxShadow: {
        'glow-red':  '0 0 20px rgba(232,0,61,0.25)',
        'glow-brand': '0 0 20px rgba(79,110,247,0.20)',
      },
    },
  },
  plugins: [],
}
