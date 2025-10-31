/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Cybersecurity dark theme palette
        cyber: {
          dark: '#0a0e27',
          darker: '#070b1f',
          card: '#0f1535',
          cardHover: '#151b42',
          border: '#1a2351',
          borderLight: '#2a3567',
        },
        neon: {
          blue: '#00d4ff',
          cyan: '#00ffff',
          purple: '#b24bf3',
          pink: '#ff006e',
          green: '#39ff14',
          red: '#ff0040',
          yellow: '#ffee00',
          orange: '#ff6b00',
        },
        threat: {
          critical: '#ff0040',
          high: '#ff6b00',
          medium: '#ffee00',
          low: '#39ff14',
          info: '#00d4ff',
        }
      },
      backgroundImage: {
        'gradient-cyber': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'gradient-neon': 'linear-gradient(135deg, #00d4ff 0%, #b24bf3 100%)',
        'gradient-threat': 'linear-gradient(135deg, #ff0040 0%, #ff6b00 100%)',
        'gradient-success': 'linear-gradient(135deg, #39ff14 0%, #00d4ff 100%)',
        'gradient-dark': 'linear-gradient(135deg, #0a0e27 0%, #151b42 100%)',
      },
      boxShadow: {
        'neon': '0 0 20px rgba(0, 212, 255, 0.5)',
        'neon-purple': '0 0 20px rgba(178, 75, 243, 0.5)',
        'neon-pink': '0 0 20px rgba(255, 0, 110, 0.5)',
        'neon-green': '0 0 20px rgba(57, 255, 20, 0.5)',
        'card': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
        'card-hover': '0 12px 40px 0 rgba(0, 212, 255, 0.2)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-up': 'slideUp 0.5s ease-out',
        'slide-down': 'slideDown 0.5s ease-out',
        'fade-in': 'fadeIn 0.6s ease-out',
        'scale-in': 'scaleIn 0.4s ease-out',
        'counter': 'counter 1s ease-out',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 212, 255, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 212, 255, 0.8)' },
        },
        slideUp: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideDown: {
          '0%': { transform: 'translateY(-20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        scaleIn: {
          '0%': { transform: 'scale(0.9)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        counter: {
          '0%': { transform: 'scale(1.2)' },
          '100%': { transform: 'scale(1)' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
