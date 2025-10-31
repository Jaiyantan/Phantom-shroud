# Phantom-shroud Frontend - ML Analytics Dashboard 🧠

Modern, dark-themed React dashboard for real-time network security monitoring and ML-based threat detection.

## 🎨 Features

### Phase 5: ML Analytics Dashboard
- **MLAnalytics**: Comprehensive ML statistics with animated counters
- **ThreatChart**: Interactive threat visualization (Doughnut/Bar charts)
- **FlowMonitor**: Real-time bidirectional flow tracking
- **MLStatus**: ML model configuration and status widget

### Design System
- **Dark Cybersecurity Theme**: Custom neon-accented color palette
- **Glass Morphism**: Frosted glass effects with backdrop blur
- **Smooth Animations**: Fade-in, slide-up, counter animations
- **Neon Glows**: Subtle glow effects on interactive elements

## 📁 Structure

```
frontend/
├── src/
│   ├── components/         # React components
│   │   ├── MLAnalytics.jsx      # ML analytics dashboard ✨
│   │   ├── ThreatChart.jsx      # Threat visualization ✨
│   │   ├── FlowMonitor.jsx      # Flow tracking ✨
│   │   ├── MLStatus.jsx         # Model status widget ✨
│   │   ├── NetworkStatus.jsx    # Network overview
│   │   ├── ThreatFeed.jsx       # Threat feed
│   │   ├── VPNControl.jsx       # VPN controls
│   │   ├── Stats.jsx            # Statistics
│   │   └── AlertPanel.jsx       # Alert notifications
│   ├── utils/              # Utilities
│   │   └── mlHooks.js           # ML API custom hooks ✨
│   ├── App.jsx             # Main app with navigation ✨
│   ├── index.css           # Enhanced global styles ✨
│   └── main.jsx            # Entry point
├── tailwind.config.js      # Enhanced Tailwind config ✨
├── package.json            # Dependencies
└── README.md               # This file
```

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm
- Backend API running on `http://localhost:5000`

### Installation

```bash
cd frontend
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Build for Production

```bash
npm run build
npm run preview
```

## 🎨 Color Palette

### Cyber Dark Theme
- `cyber-dark`: #0a0e27 (Main background)
- `cyber-card`: #0f1535 (Card background)
- `cyber-border`: #1a2351 (Borders)

### Neon Accents
- `neon-blue`: #00d4ff (Primary)
- `neon-purple`: #b24bf3 (Secondary)
- `neon-green`: #39ff14 (Success)
- `neon-red`: #ff0040 (Critical)

## 🔌 ML API Integration

### Custom Hooks (`src/utils/mlHooks.js`)

```javascript
import { useMLStats, useMLThreats, useMLFlows, useMLStatus } from '../utils/mlHooks';

// Auto-refreshing ML statistics (5s interval)
const { data, loading, error, lastUpdate } = useMLStats(5000);

// Other hooks
useMLStatus(10000)   // Model status
useMLFlows(3000)     // Active flows
useMLThreats(4000)   // Detected threats
```

### API Endpoints

| Endpoint | Refresh | Description |
|----------|---------|-------------|
| `/api/security/ml/stats` | 5s | Full ML statistics |
| `/api/security/ml/status` | 10s | Model configuration |
| `/api/security/ml/flows` | 3s | Active flows |
| `/api/security/ml/threats` | 4s | Detected threats |

## 📊 Components

### 1. MLAnalytics (Main Dashboard)
- Real-time packet statistics with animated counters
- Cache performance metrics
- Queue utilization monitoring
- System performance indicators
- Graceful degradation when ML unavailable

### 2. ThreatChart (Visualization)
- Interactive Doughnut/Bar chart toggle
- 8 threat categories with color coding
- Threat severity levels (Critical/High/Medium/Low)
- Category breakdown with detection counts
- Smooth chart animations

### 3. FlowMonitor (Flow Tracking)
- Bidirectional flow statistics
- Protocol filtering (TCP/UDP/All)
- Sorting by packets/bytes/duration
- Forward/backward packet indicators
- Expandable flow details

### 4. MLStatus (Model Widget)
- ML availability indicator
- GPU/CPU device badge
- Model configuration details
- Threat category listing
- Setup instructions for unavailable state

## 🎭 Animation System

Built-in Tailwind animations:
```css
animate-fade-in      /* Fade in effect */
animate-slide-up     /* Slide up from bottom */
animate-slide-down   /* Slide down from top */
animate-scale-in     /* Scale in effect */
animate-counter      /* Number counter animation */
animate-glow         /* Neon glow effect */
```

## 🛠️ Tech Stack

- **React 18** - UI framework
- **Vite** - Build tool and dev server
- **Tailwind CSS 3** - Utility-first styling
- **Chart.js** - Data visualization
- **Socket.IO Client** - Real-time updates

## 🌐 Navigation

The app features two main views:

1. **Overview** 📊
   - Network Status
   - Threat Feed
   - VPN Control
   - Statistics

2. **ML Analytics** 🧠 ✨
   - ML Statistics
   - Threat Visualization
   - Flow Monitor
   - Model Status

Toggle between views using the navigation tabs in the header.

## 🎯 Development Tips

### Adding Components
```jsx
// Use Tailwind cyber theme classes
<div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
  {/* Content */}
</div>
```

### Using ML Hooks
```jsx
const { data, loading, error } = useMLStats(5000);

if (loading) return <div>Loading...</div>;
if (error) return <div>Error: {error.message}</div>;
return <div>{data.total_analyzed} packets</div>;
```

## 🚨 Error Handling

### ML Not Available (503)
- Shows installation instructions
- Links to documentation
- Gracefully disables ML features

### Network Errors
- Auto-retry mechanism
- User-friendly error messages
- Fallback to cached data

## 📝 Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

---

**Phase 5 Integration** - ML Analytics Dashboard  
**Built for** CICADA'25 Hackathon  
**Status**: ✅ Production-ready
