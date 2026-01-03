# WiFi Attack Detection Tools - Usage Guide

## Overview
These tools help detect if attackers are collecting data after deauthentication attacks by monitoring for:

1. **Evil Twin APs** - Fake access points with same SSID
2. **Handshake Captures** - WPA credential harvesting attempts  
3. **Rogue Networks** - New suspicious networks appearing
4. **Reconnaissance** - Excessive probing and scanning

## Quick Setup

### 1. Prepare Kali Linux
```bash
# Put your WiFi adapter in monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode (should show wlan0mon)
iwconfig
```

### 2. Make Scripts Executable
```bash
chmod +x /path/to/wifi_attack_detector.sh
chmod +x /path/to/advanced_wifi_analyzer.py
```

## Tool Usage

### Basic Detection Script
```bash
# Run comprehensive 60-second scan
sudo ./wifi_attack_detector.sh

# Results will be saved to /home/d4kAdude88/CYBER_EVIDENCE_ATTACK/
```

**What it detects:**
- Rogue APs with duplicate SSIDs
- Real-time deauth attacks (including your logged attacks)
- WPA handshake capture attempts
- Network topology changes
- Suspicious DHCP activity

### Advanced Python Analyzer
```bash
# Run 5-minute analysis (default)
sudo python3 advanced_wifi_analyzer.py -i wlan0mon

# Run 10-minute analysis
sudo python3 advanced_wifi_analyzer.py -i wlan0mon -t 600

```

**What it detects:**
- Correlates deauth attacks with data collection attempts
- Identifies evil twin deployments after deauth
- Tracks handshake capture sequences
- Reconnaissance pattern detection

## Indicators of Data Collection

### 🚨 HIGH RISK - Active Data Theft
- **Evil Twin Detection**: Same SSID, different BSSID appearing after deauth
- **Handshake Captures**: EAPOL frames captured within 60 seconds of deauth
- **Credential Harvesting**: Captive portals or fake login pages

### ⚠️ MEDIUM RISK - Preparation Phase
- **New Networks**: Unknown APs appearing during attack window
- **Excessive Probing**: High volume of probe requests from single MAC
- **Channel Scanning**: Rapid channel hopping patterns

### ℹ️ LOW RISK - Reconnaissance Only
- **Passive Scanning**: Normal probe requests
- **Network Enumeration**: SSID discovery without follow-up

### Targeted Monitoring
```bash
# Monitor specific BSSID for data collection
sudo tshark -i wlan0mon -f "wlan addr1 <MAC ADDRESS> or wlan addr2 <MAC ADDRESS>"

# Look for handshakes on specific network
sudo tshark -i wlan0mon -f "ether proto 0x888e" | grep "<MAC ADDRESS>"
```

## Real-Time Correlation Analysis

### Manual Correlation Check
1. **Run deauth monitoring** to see active attacks
2. **Watch for immediate responses**:
   - New SSID with same name as target
   - Handshake frames within 60 seconds
   - DHCP servers appearing on new networks

### Automated Detection
```bash
# Run both tools simultaneously in different terminals

# Terminal 1: Real-time attack detection
sudo ./wifi_attack_detector.sh

# Terminal 2: Advanced correlation analysis  
sudo python3 advanced_wifi_analyzer.py -t 600
```

## Sample Attack Sequence to Watch For

1. **Deauth Attack**: Target gets disconnected
   ```
   SPOOFED DEAUTH ATTACK: <MAC ADDRESS> | Reason: 2
   ```

2. **Evil Twin Deployment**: Fake AP appears
   ```
   EVIL TWIN DETECTED: HomeWiFi | Rogue BSSID: <MAC ADDRESS>
   ```

3. **Client Reconnection**: Victim connects to fake AP
   ```
   HANDSHAKE FRAME: <MAC ADDRESS> | Type: 1
   ```

4. **Data Collection**: Traffic interception begins
   ```
   DHCP ACTIVITY: Rogue server assigning IPs
   ```

## Interpretation Guide

### Safe Scenarios
- Only deauth attacks with no follow-up activity
- No new networks appearing after attacks
- No handshake captures

### Concerning Scenarios  
- Evil twins appearing within minutes of deauth
- Handshake captures immediately after deauth
- New DHCP servers on unknown networks

### Critical Scenarios
- Multiple evil twins targeting same victims
- Coordinated deauth + rogue AP deployment
- Active credential harvesting portals

## Protection Recommendations

### For Monitored Networks
1. **Enable PMF** (Protected Management Frames)
2. **Use WPA3** where possible
3. **Monitor for rogue APs** regularly
4. **Educate users** about evil twin risks

### For Your Monitoring
1. **Document attack signatures** for threat intelligence
2. **Correlate with ISP reports** of service issues
3. **Share findings** with local cybersecurity community
4. **Consider law enforcement** reporting for persistent campaigns

## File Outputs

- `/path/to/output/` - All detection results and evidence
- `/path/to/output/attack_analysis_report.json` - Advanced analysis
- Log files with timestamps for evidence preservation

## Next Steps

1. **Run initial baseline scan** to map legitimate networks
2. **Monitor during peak attack times** (based on your logs)
3. **Correlate with service disruption reports** from targeted networks
4. **Document evidence** for potential reporting to authorities

The key is correlation - deauth attacks alone are concerning, but deauth + immediate data collection attempts indicate active credential theft operations.