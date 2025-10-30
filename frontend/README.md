# Phantom-shroud Frontend

This directory contains the React-based admin dashboard for Phantom-shroud.

## Structure

```
frontend/
├── src/
│   ├── components/    # React components
│   ├── utils/         # Frontend utilities
│   ├── App.jsx        # Main application component
│   └── main.jsx       # Application entry point
├── public/            # Static assets
├── index.html         # HTML template
├── package.json       # Node.js dependencies
├── vite.config.js     # Vite build configuration
└── tailwind.config.js # Tailwind CSS configuration
```

## Tech Stack

- **React** - UI framework
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Styling framework

## Setup

```bash
cd frontend
npm install
```

## Development

```bash
npm run dev
```

The dashboard will be available at `http://localhost:5173`

## Build for Production

```bash
npm run build
```

## Features

- Real-time network monitoring
- Threat feed visualization
- VPN control panel
- Alert notifications
- Network statistics dashboard
