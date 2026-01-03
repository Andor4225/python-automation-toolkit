# Wireless Forensics Analyzer

A real-time wireless forensics platform for processing ESP32 WiFi, nRF Bluetooth, and network traffic captures. Built on an Adapter Pattern architecture for extensible multi-protocol analysis with integrated security threat detection and spatial intelligence.

## Overview

Wireless Forensics Analyzer processes PCAP files from multiple capture sources and generates comprehensive security analysis reports. The system provides real-time monitoring, device tracking, threat detection, and RSSI-based triangulation for location-aware threat intelligence.

## Features

### Multi-Protocol Packet Processing
- **ESP32 WiFi Analysis** — Management frame parsing (beacons, probes, deauth, disassoc), device tracking, and RSSI extraction
- **nRF Bluetooth Analysis** — BLE device detection with signal strength correlation
- **Network Traffic Analysis** — Honeypot and VLAN traffic monitoring with complete flow analysis

### Security Event Detection
- **Deauthentication Attack Detection** — Real-time identification of deauth frames
- **Disassociation Attack Detection** — Detection of malicious disassoc frames
- **Deauth Flood Detection** — Identifies >20 deauth frames within 60 seconds
- **Real-Time Alerting** — Console notifications for detected threats
- **Event Aggregation** — Intelligent grouping of related security events

### Spatial Intelligence (Triangulation)
- **Multi-Position Analysis** — Process multiple RSSI captures for device positioning
- **Router-Referenced Positioning** — Coordinate system centered on known reference points
- **Proximity Classification** — Immediate, close, neighbor, and distant zone categorization
- **Threat Proximity Scoring** — 0-100 risk assessment based on distance and security events
- **Movement Detection** — Signal variance analysis for mobile vs. stationary devices

### Cross-Protocol Correlation
- **WiFi ↔ Bluetooth Device Pairing** — Identify devices belonging to the same individual
- **Manufacturer Matching** — OUI-based correlation across protocols
- **Temporal Correlation** — Activity timing and pattern matching
- **Ecosystem Detection** — Apple, Google, Amazon device constellation identification

### Data Optimization
- **RSSI Statistics Computation** — Replace large arrays with computed min/max/avg/stddev
- **Configurable Packet Limits** — Balance processing speed with data completeness
- **Aggressive Trimming** — 60-90% file size reduction while preserving analytics

## System Architecture

```
WirelessForensicsAnalyzer/
├── data_model.py                  # Data structures (WiFiDeviceData, BluetoothDeviceData, etc.)
├── adapter_interfaces.py          # Protocol-specific parsers
├── file_watcher.py                # Real-time file monitoring
├── main_analyzer_orchestrator.py  # Main coordinator
└── main_wireshark_execution.py    # Entry point
```

### Design Patterns

| Pattern | Implementation |
|---------|----------------|
| Adapter Pattern | Dedicated parsers for each protocol (ESP32WiFiAdapter, nRFBluetoothAdapter, NetworkTrafficAdapter) |
| Observer Pattern | File watcher monitors directories for new PCAP files |
| Strategy Pattern | Configurable analysis modes and packet limits |

## Requirements

- Python 3.10+
- PyShark
- tshark (Wireshark CLI)
- 8GB+ RAM recommended for large captures

### Dependencies

```bash
pip install pyshark
```

Ensure `tshark` is installed and available in your system PATH.

## Usage

### Basic Analysis

```bash
python main_wireshark_execution.py
```

The analyzer monitors the configured input directory for PCAP files and automatically processes new captures.

### Supported File Types

| File Pattern | Protocol | Description |
|--------------|----------|-------------|
| `raw_*.pcap` | WiFi | Full packet capture with management frames |
| `rssi*.pcap` | WiFi | Signal strength focused captures for triangulation |
| `nRF_*.pcap` | Bluetooth | nRF sniffer BLE captures |
| `honeypot-*.pcap` | Network | Honeypot traffic captures |

### Output

Analysis results are consolidated into a single JSON file containing:

- Device inventory with MAC addresses, SSIDs, and metadata
- RSSI statistics per device
- Security events with timestamps and targets
- Triangulation data with position estimates
- Cross-protocol correlation results

### JSON Output Structure

```json
{
  "wifi_devices": [...],
  "bluetooth_devices": [...],
  "network_connections": [...],
  "security_events": {
    "event_count": 949,
    "aggregated_events": [...]
  },
  "triangulation_analysis": {
    "multi_position_devices": [...],
    "spatial_intelligence": {...}
  },
  "device_correlation": {
    "high_confidence_matches": [...],
    "possible_matches": [...]
  }
}
```

## Configuration

### Packet Limits

Adjust packet limits in the orchestrator for performance tuning:

| File Type | Default Limit | Use Case |
|-----------|---------------|----------|
| `raw_*.pcap` | Unlimited | Full device detection |
| `rssi*.pcap` | 5,000 | Triangulation analysis |
| `nRF_*.pcap` | 5,000 | Bluetooth correlation |

### Triangulation Setup

For spatial intelligence, capture RSSI data from multiple known positions:

1. **Position 1** — Reference point (coordinates 0,0)
2. **Position 2** — Known distance from Position 1
3. **Position 3** — Third reference for improved accuracy

Save captures as `rssi1.pcap`, `rssi2.pcap`, `rssi3.pcap`.

## Security Detection Capabilities

### Threat Types Detected

- Deauthentication attacks
- Disassociation attacks
- Deauth flood attacks
- Beacon flooding (configurable)
- Evil twin detection (via SSID analysis)

### Correlation-Based Threats

- Multi-vector attack correlation (WiFi + Bluetooth)
- Device impersonation detection
- Suspicious pairing pattern identification

## Performance Metrics

Tested performance on representative captures:

| Metric | Value |
|--------|-------|
| Packets processed | 70,000+ per file |
| Devices detected | 160+ per analysis |
| Security events | 900+ with aggregation |
| Processing time | Minutes for large captures |

## Technical Notes

### Frame Control Parsing

WiFi management frame detection uses direct bit manipulation of the frame control field:

```python
frame_type = (fc_value >> 2) & 0x3
frame_subtype = (fc_value >> 12) & 0xF
```

### RSSI Extraction Paths

Multiple fallback paths for signal strength extraction:

- `radiotap.dbm_antsignal`
- `wlan_radio.signal_dbm`
- `btle.rssi`

### Indoor Propagation Model

Distance estimation uses log-distance path loss with indoor compensation factor (3.0x) for residential environments.

## Roadmap

### Planned Enhancements

- Heat map generation for visual threat mapping
- Geofencing alerts with automated boundary breach detection
- Real-time triangulation during live capture
- MAC randomization detection and correlation
- Extended behavioral pattern analysis

## License

MIT License — See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome. Please open an issue to discuss proposed changes before submitting a pull request.

## Acknowledgments

Built with PyShark for robust packet parsing and tshark backend integration.
