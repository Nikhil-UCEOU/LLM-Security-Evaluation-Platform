/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0f4ff',
          500: '#4f6ef7',
          600: '#3b55e6',
          700: '#2d44cc',
          900: '#1a2a8a',
        },
        danger: {
          50: '#fff1f0',
          500: '#ff4d4f',
          600: '#e63946',
        },
        success: {
          500: '#52c41a',
        },
        warning: {
          500: '#faad14',
        },
      },
    },
  },
  plugins: [],
}
