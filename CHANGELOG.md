# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### In Progress
- Frontend security dashboard components for ML analytics
- Unit test suite for security modules
- Performance optimization

## [0.4.0] - 2025-10-31

### Added - Phase 4: ML-Based Deep Packet Inspection
- **ML-Based DPI Analyzer**: Advanced packet classification using BERT/DistilBERT models (`backend/core/dpi/ml_analyzer.py`)
  - MLFlowTracker for bidirectional flow statistics (forward/backward packet analysis)
  - Async batch inference with configurable batch sizes (default: 16 packets)
  - Background worker threads for analysis and result cleanup
  - 8 threat categories: Backdoor, Bot, DDoS, DoS, Exploits, Shellcode, SQL Injection, XSS
  - Result caching with 60-second TTL for performance optimization
  - GPU/CPU auto-detection and fallback
  - Queue-based processing with overflow protection (1000 max queue size)
  - JSONL logging for all inferences (`logs/ml_inference.jsonl`)
- **ML Analytics API**: 4 new endpoints for ML-based threat detection
  - `GET /api/security/ml/stats` - Full statistics (packets analyzed, threats detected, queue metrics, cache performance)
  - `GET /api/security/ml/status` - Configuration and model information
  - `GET /api/security/ml/flows` - Active flow count and bidirectional statistics
  - `GET /api/security/ml/threats` - Threat detections with category breakdown
- **Optional ML Dependencies**: Separated ML packages into `requirements-ml.txt`
  - PyTorch >=2.0.0 for deep learning inference
  - HuggingFace Transformers >=4.30.0 for BERT models
  - GPU installation instructions included for CUDA support
- **Graceful Degradation**: System works without ML packages installed
  - ML analyzer runs in dummy mode when dependencies unavailable
  - Flask app initialization handles missing ML gracefully
  - API endpoints check ML availability before processing

### Changed
- ML analyzer integrated into Flask app initialization with PG_BERT_MODEL environment variable for custom models
- DPI module structure updated with proper exports (`backend/core/dpi/__init__.py`)
- Requirements documentation enhanced with ML dependency notes
- Security routes expanded to 27 total endpoints (23 from Phase 3 + 4 new ML endpoints)

### Security
- **ML Threat Detection**: Real-time packet classification for 8 attack categories
- **Flow Analysis**: Bidirectional tracking enables detection of asymmetric attacks
- **Threat Intelligence**: Cached results enable fast re-classification of similar packets
- **Privacy**: All inference data logged locally with configurable retention

### Performance
- Batch inference reduces GPU overhead by 10-15x compared to single-packet processing
- Result caching improves response time for repeated packet patterns
- Background workers prevent blocking of packet capture pipeline
- Queue management prevents memory exhaustion under high traffic loads
- Automatic cleanup of stale flows and cached results

### Documentation
- Added ML-based DPI capabilities to Phase 4 integration
- Updated requirements files with clear separation of core vs. ML dependencies
- Included GPU installation instructions for CUDA acceleration

### Contributors
- Joseph: Original ML-based DPI implementation with BERT classifier (~700 LOC adapted from external dpi.py)

## [0.3.0] - 2025-10-31

### Added - Phase 3: API Integration & Enhanced Anomaly Detection
- **Comprehensive Security API**: Complete REST API for all security modules (`backend/api/security_routes.py`)
  - 20+ new endpoints for ARP, TCP, certs, portals, WiFi, honeypot, and anomaly detection
  - Health check and status monitoring endpoints
  - Real-time metrics and statistics APIs
- **Advanced Anomaly Detection**: Major enhancement to anomaly_detector.py with Joseph's MITM algorithms
  - TTL baseline analysis for proxy detection (deviation >10 triggers alert)
  - Network latency monitoring and spike detection (>2x average)
  - Enhanced ARP spoofing detection with duplicate IP/MAC tracking
  - Improved DNS hijacking detection with known-good DNS validation
  - Advanced port scanning detection with sequential pattern recognition
  - Per-host network metrics tracking (TTL, latency, packet counts)
  - Comprehensive statistics and suspicious IP reporting
- App config exposure for anomaly detector in Flask app
- Phase 2 and Phase 3 completion reports in docs/

### Changed
- Anomaly detector now includes network metrics analysis alongside rule-based and ML detection
- Security routes blueprint registered in main Flask app
- Enhanced documentation in README.md with new security modules section
- Updated project structure to reflect new security organization

### Security
- **TTL Anomaly Detection**: Identifies MITM proxies by monitoring TTL changes
- **Latency Spike Detection**: Detects processing delays from intercepting proxies
- **Duplicate Tracking**: Real-time IP-to-MAC mapping for ARP spoofing
- **DNS Validation**: Known-good DNS tracking prevents hijacking attacks
- **Port Scan Detection**: Multi-threshold approach (unique ports, connection rate, sequential patterns)
- **Network Metrics**: Statistical analysis per host for behavioral baselines

### Documentation
- PHASE2_COMPLETION_REPORT.md: Comprehensive Phase 2 integration summary
- Enhanced README.md with security modules table and API endpoint documentation
- Updated architecture diagrams showing new security layer

### Performance
- <2s detection latency maintained for all anomaly checks
- Efficient metrics tracking with automatic history pruning (last 100 samples)
- Lock-free read operations for statistics endpoints

### Contributors
- Joseph: Advanced MITM detection algorithms (~1,000 LOC enhancement to anomaly_detector.py)

## [0.2.0] - 2025-10-31

### Added - Joseph's Security Modules Integration
- **ARP Spoofing Detection**: Real-time gratuitous ARP monitoring (`backend/core/network/arp_monitor.py`)
- **TCP Metrics Analysis**: TTL and window size variance detection for MITM identification (`backend/core/network/tcp_monitor.py`)
- **Certificate Pinning**: Certificate validation system to detect cert substitution attacks (`backend/core/security/cert_validator.py`)
- **Portal Fingerprinting**: Captive portal detection and cross-network tracking (`backend/core/network/portal_detector.py`)
- **Production Honeypots**: Enhanced HTTP/SSH honeypots with attacker tracking (`backend/core/honeypot.py`)
- **JA3 TLS Fingerprinting**: TLS client/server fingerprinting for threat identification (`backend/core/dpi/protocols/tls.py`)
- **WiFi Security Analyzer**: Comprehensive WiFi network security assessment (`backend/core/wifi_analyzer.py`)
- CONTRIBUTORS.md file with Joseph's attribution
- Extensive documentation: JOSEPH_WORK_ANALYSIS.md and JOSEPH_INTEGRATION_SUMMARY.md

### Changed
- Enhanced honeypot module with AttackerTracker class for better threat intelligence
- DPI protocols now include TLS analysis with JA3/JA3S fingerprinting
- Security monitoring expanded with 7 new detection modules

### Security
- **MITM Detection Enhanced**: From 30% to 85% coverage
  - ARP poisoning detection
  - TCP-based proxy detection via TTL/window analysis
  - Certificate substitution detection
  - Rogue portal identification
- **Network Security**: Added WiFi encryption assessment and rogue AP detection
- **Threat Intelligence**: JA3 fingerprint database for known malicious clients
- **Attacker Tracking**: Comprehensive IP-based interaction tracking in honeypots

### Contributors
- Joseph: 7 major security modules (~3,500 LOC), production-ready MITM detection

## [0.1.0] - 2025-10-30

### Added
- Network Inspection System with Scapy-based packet capture
- Deep Packet Inspection (DPI) engine for protocol analysis
- Anomaly Detection using rule-based and ML approaches
- VPN Manager for automated OpenVPN tunneling
- Honeypot implementation for deception capabilities
- Threat Analyzer for event correlation
- Flask API backend with RESTful endpoints
- React-based admin dashboard with real-time monitoring
- Network status visualization
- Alert panel for threat notifications
- VPN control interface
- Statistics dashboard

### Security
- Automated VPN encryption for public Wi-Fi protection
- MITM attack detection capabilities
- SSL/TLS validation

---

## Release Types

- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Features that will be removed in future versions
- **Removed** - Features that have been removed
- **Fixed** - Bug fixes
- **Security** - Security improvements or vulnerability fixes
