import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // AegisVault dark premium color system
        aegis: {
          // Backgrounds
          bg:          '#0D0D12',
          surface:     '#13131A',
          elevated:    '#1A1A24',
          overlay:     '#20202E',
          // Borders
          border:      '#252535',
          'border-hover': '#353550',
          // Text
          text:        '#F1F5F9',
          subtle:      '#94A3B8',
          muted:       '#475569',
          // Brand
          primary:     '#6366F1',
          'primary-hover': '#4F46E5',
          'primary-muted': '#312E81',
          // States
          danger:      '#EF4444',
          'danger-hover': '#DC2626',
          'danger-muted': '#450A0A',
          warning:     '#F59E0B',
          'warning-muted': '#451A03',
          success:     '#10B981',
          'success-muted': '#022C22',
          // High-risk (crypto secrets)
          highrisk:    '#F97316',
          'highrisk-muted': '#431407',
        },
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-jetbrains-mono)', 'Consolas', 'monospace'],
      },
      borderRadius: {
        'aegis': '8px',
        'aegis-lg': '12px',
        'aegis-xl': '16px',
      },
      animation: {
        'fade-in': 'fadeIn 0.15s ease-out',
        'slide-up': 'slideUp 0.2s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      boxShadow: {
        'aegis': '0 1px 3px 0 rgb(0 0 0 / 0.5), 0 1px 2px -1px rgb(0 0 0 / 0.5)',
        'aegis-lg': '0 10px 25px -3px rgb(0 0 0 / 0.6), 0 4px 6px -4px rgb(0 0 0 / 0.5)',
        'aegis-glow': '0 0 0 1px rgb(99 102 241 / 0.3), 0 0 20px rgb(99 102 241 / 0.1)',
        'danger-glow': '0 0 0 1px rgb(239 68 68 / 0.3), 0 0 20px rgb(239 68 68 / 0.1)',
      },
    },
  },
  plugins: [],
};

export default config;
