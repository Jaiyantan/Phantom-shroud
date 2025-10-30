# Phantom-shroud Backend

This directory contains the backend Python application for Phantom-shroud.

## Structure

```
backend/
├── api/              # Flask API endpoints
├── core/             # Core security modules (DPI, VPN, honeypot, etc.)
├── config/           # Configuration files and VPN profiles
├── utils/            # Utility functions and helpers
├── tests/            # Unit and integration tests
├── data/             # Runtime data storage
├── logs/             # Application logs
├── models/           # ML models for anomaly detection
├── scripts/          # Helper scripts
├── requirements.txt  # Python dependencies
└── setup.sh          # Backend setup script
```

## Setup

```bash
cd backend
pip install -r requirements.txt
./setup.sh
```

## Running the API

```bash
cd backend
python api/app.py
```

## Testing

```bash
cd backend
pytest tests/
```

## Documentation

See the [docs](../docs/) directory for detailed architecture and implementation guides.
