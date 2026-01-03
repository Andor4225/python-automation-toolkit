#!/bin/bash
# WiFi Attack Detection Script - BULLETPROOF VERSION
# Detects: Rogue APs, Evil Twins, Handshake Captures, Deauth Attacks
# Usage: Run on Kali Linux with monitor mode interface

echo "=== WiFi Attack Detection & Monitoring Suite ==="
echo "Detecting: Rogue APs, Evil Twins, Handshake Captures"
echo "Date: $(date)"
echo

# Configuration
INTERFACE="<your_monitor_interface>"  # Change to your monitor interface
SCAN_TIME=<your_scan_time>       # Seconds to scan
OUTPUT_DIR="/path/to/output"  # Change to desired output directory
LOGFILE="$OUTPUT_DIR/attack_detection_$(date +%Y%m%d_%H%M%S).log"

# Function to safely convert to number (returns 0 if not a number)
safe_number() {
    local value="$1"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "0"
    fi
}

# Function to log with timestamp
log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Function to check if interface is in monitor mode
check_monitor_mode() {
    if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
        echo "Error: $INTERFACE is not in monitor mode"
        echo "Run: sudo airmon-ng start mon0"
        exit 1
    fi
    log_event "Monitor interface $INTERFACE confirmed"
}

# Function to detect rogue APs (same SSID, different BSSID)
detect_rogue_aps() {
    log_event "Scanning for rogue APs and evil twins..."
    
    # Scan for networks
    timeout $SCAN_TIME airodump-ng --write "$OUTPUT_DIR/scan" --output-format csv "$INTERFACE" >/dev/null 2>&1
    
    if [[ -f "$OUTPUT_DIR/scan-01.csv" ]]; then
        # Parse CSV and detect duplicate SSIDs
        awk -F',' '
        NR>2 && $14!="" && $14!=" " && $14!="," {
            gsub(/^[ \t]+|[ \t]+$/, "", $14)  # Trim whitespace
            ssid=$14
            bssid=$1
            gsub(/^[ \t]+|[ \t]+$/, "", bssid)  # Trim whitespace
            channel=$4
            privacy=$6
            power=$9
            
            # Store SSID->BSSID mapping
            if(ssid in ssids && ssid != "") {
                if(ssids[ssid] != bssid) {
                    print "ROGUE AP DETECTED:"
                    print "  SSID: " ssid
                    print "  Original BSSID: " ssids[ssid]
                    print "  Rogue BSSID: " bssid
                    print "  Channel: " channel
                    print "  Power: " power " dBm"
                    print "  Security: " privacy
                    print "  Timestamp: " strftime("%Y-%m-%d %H:%M:%S")
                    print "---"
                }
            } else if(ssid != "") {
                ssids[ssid] = bssid
            }
        }' "$OUTPUT_DIR/scan-01.csv" | tee -a "$LOGFILE"
    fi
}

# Function to monitor for handshake captures
monitor_handshakes() {
    log_event "Monitoring for WPA handshake capture attempts..."
    
    # Use tshark to monitor for EAPOL frames (handshakes)
    timeout $SCAN_TIME tshark -i "$INTERFACE" -f "ether proto 0x888e" \
        -T fields -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid -e eapol.type \
        2>/dev/null | while read line; do
        
        if [[ -n "$line" ]]; then
            timestamp=$(echo "$line" | cut -f1)
            src=$(echo "$line" | cut -f2)
            dst=$(echo "$line" | cut -f3)
            bssid=$(echo "$line" | cut -f4)
            eapol_type=$(echo "$line" | cut -f5)
            
            log_event "HANDSHAKE FRAME: $timestamp | BSSID: $bssid | SRC: $src | DST: $dst | Type: $eapol_type"
        fi
    done
}

# Function to detect deauth attacks in real-time
monitor_deauth_attacks() {
    log_event "Monitoring for active deauth attacks..."
    
    timeout $SCAN_TIME tshark -i "$INTERFACE" \
        -f "wlan type mgt subtype deauth" \
        -T fields -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.fixed.reason_code \
        2>/dev/null | while read line; do
        
        if [[ -n "$line" ]]; then
            timestamp=$(echo "$line" | cut -f1)
            src=$(echo "$line" | cut -f2)
            dst=$(echo "$line" | cut -f3)
            bssid=$(echo "$line" | cut -f4)
            reason=$(echo "$line" | cut -f5)
            
            # Check for attack signatures
            if [[ "$src" == "$dst" && "$src" == "$bssid" ]]; then
                log_event "SPOOFED DEAUTH ATTACK: $timestamp | Target: $bssid | Reason: $reason"
            elif [[ "$reason" == "0" ]]; then
                log_event "MALICIOUS DEAUTH (Reason 0): $timestamp | SRC: $src | Target: $bssid"
            else
                log_event "DEAUTH FRAME: $timestamp | SRC: $src | DST: $dst | BSSID: $bssid | Reason: $reason"
            fi
        fi
    done
}

# Function to analyze network changes
analyze_network_changes() {
    log_event "Analyzing network topology changes..."
    
    # Compare with baseline if exists
    BASELINE="$OUTPUT_DIR/baseline_networks.txt"
    CURRENT="$OUTPUT_DIR/current_networks.txt"
    
    if [[ -f "$OUTPUT_DIR/scan-01.csv" ]]; then
        # Extract current network list
        awk -F',' 'NR>2 && $14!="" && $14!=" " && $14!="," {print $1 "," $14 "," $4}' "$OUTPUT_DIR/scan-01.csv" > "$CURRENT"
        
        if [[ -f "$BASELINE" ]]; then
            # Compare with baseline
            log_event "Network changes detected:"
            diff "$BASELINE" "$CURRENT" | grep "^>" | while read line; do
                network=$(echo "$line" | cut -c3-)
                bssid=$(echo "$network" | cut -d',' -f1)
                ssid=$(echo "$network" | cut -d',' -f2)
                channel=$(echo "$network" | cut -d',' -f3)
                log_event "NEW NETWORK: BSSID: $bssid | SSID: $ssid | Channel: $channel"
            done
        else
            # Create baseline
            cp "$CURRENT" "$BASELINE"
            log_event "Baseline network list created with $(wc -l < "$CURRENT") networks"
        fi
    fi
}

# Function to check for suspicious DHCP activity
monitor_dhcp_activity() {
    log_event "Monitoring for suspicious DHCP activity..."
    
    timeout $SCAN_TIME tshark -i "$INTERFACE" \
        -f "port 67 or port 68" \
        -T fields -e frame.time -e ip.src -e ip.dst -e dhcp.option.dhcp_server_id \
        2>/dev/null | while read line; do
        
        if [[ -n "$line" ]]; then
            timestamp=$(echo "$line" | cut -f1)
            src=$(echo "$line" | cut -f2)
            dst=$(echo "$line" | cut -f3)
            server_id=$(echo "$line" | cut -f4)
            
            log_event "DHCP ACTIVITY: $timestamp | SRC: $src | DST: $dst | Server: $server_id"
        fi
    done
}

# Function to count events safely
count_events() {
    local pattern="$1"
    local file="$2"
    local count
    
    if [[ -f "$file" ]]; then
        count=$(grep -c "$pattern" "$file" 2>/dev/null)
        # Make sure count is a valid number
        count=$(safe_number "$count")
    else
        count=0
    fi
    
    echo "$count"
}

# Function to generate summary report
generate_report() {
    log_event "Generating detection summary report..."
    
    echo "=== WiFi Attack Detection Summary ===" > "$OUTPUT_DIR/summary_report.txt"
    echo "Scan Date: $(date)" >> "$OUTPUT_DIR/summary_report.txt"
    echo "Scan Duration: $SCAN_TIME seconds" >> "$OUTPUT_DIR/summary_report.txt"
    echo "Log File: $LOGFILE" >> "$OUTPUT_DIR/summary_report.txt"
    echo >> "$OUTPUT_DIR/summary_report.txt"
    
    # Count different types of events using safe counting function
    rogue_aps=$(count_events "ROGUE AP DETECTED" "$LOGFILE")
    handshakes=$(count_events "HANDSHAKE FRAME" "$LOGFILE")
    spoofed_deauth=$(count_events "SPOOFED DEAUTH ATTACK" "$LOGFILE")
    malicious_deauth=$(count_events "MALICIOUS DEAUTH" "$LOGFILE")
    deauth_frames=$(count_events "DEAUTH FRAME" "$LOGFILE")
    
    # Double-check all variables are numbers
    rogue_aps=$(safe_number "$rogue_aps")
    handshakes=$(safe_number "$handshakes")
    spoofed_deauth=$(safe_number "$spoofed_deauth")
    malicious_deauth=$(safe_number "$malicious_deauth")
    deauth_frames=$(safe_number "$deauth_frames")
    
    echo "Detection Results:" >> "$OUTPUT_DIR/summary_report.txt"
    echo "  Rogue APs Detected: $rogue_aps" >> "$OUTPUT_DIR/summary_report.txt"
    echo "  Handshake Captures: $handshakes" >> "$OUTPUT_DIR/summary_report.txt"
    echo "  Spoofed Deauth Attacks: $spoofed_deauth" >> "$OUTPUT_DIR/summary_report.txt"
    echo "  Malicious Deauth (Reason 0): $malicious_deauth" >> "$OUTPUT_DIR/summary_report.txt"
    echo "  Total Deauth Frames: $deauth_frames" >> "$OUTPUT_DIR/summary_report.txt"
    echo >> "$OUTPUT_DIR/summary_report.txt"
    
    # Risk assessment with bulletproof arithmetic
    # First verify all variables are actually numbers
    if [[ "$rogue_aps" =~ ^[0-9]+$ ]] && [[ "$spoofed_deauth" =~ ^[0-9]+$ ]] && [[ "$malicious_deauth" =~ ^[0-9]+$ ]]; then
        total_threats=$((rogue_aps + spoofed_deauth + malicious_deauth))
    else
        # Fallback: manually count
        total_threats=0
        [[ "$rogue_aps" =~ ^[0-9]+$ ]] && total_threats=$((total_threats + rogue_aps))
        [[ "$spoofed_deauth" =~ ^[0-9]+$ ]] && total_threats=$((total_threats + spoofed_deauth))
        [[ "$malicious_deauth" =~ ^[0-9]+$ ]] && total_threats=$((total_threats + malicious_deauth))
    fi
    
    # Determine threat level
    if [[ $total_threats -gt 10 ]]; then
        threat_level="HIGH"
    elif [[ $total_threats -gt 5 ]]; then
        threat_level="MEDIUM"
    elif [[ $total_threats -gt 0 ]]; then
        threat_level="LOW-MEDIUM"
    else
        threat_level="LOW"
    fi
    
    # Special case: any rogue APs automatically make it high threat
    if [[ $rogue_aps -gt 0 ]]; then
        threat_level="HIGH"
    fi
    
    echo "Threat Level: $threat_level" >> "$OUTPUT_DIR/summary_report.txt"
    echo "Total Threat Events: $total_threats" >> "$OUTPUT_DIR/summary_report.txt"
    
    # Add context for findings
    if [[ $rogue_aps -gt 0 ]]; then
        echo >> "$OUTPUT_DIR/summary_report.txt"
        echo "🚨 CRITICAL: Rogue AP detected! Possible evil twin attack in progress." >> "$OUTPUT_DIR/summary_report.txt"
    fi
    
    if [[ $deauth_frames -gt 0 ]]; then
        echo >> "$OUTPUT_DIR/summary_report.txt"
        echo "⚠️  WARNING: Deauth attacks detected. Networks under attack." >> "$OUTPUT_DIR/summary_report.txt"
    fi
    
    if [[ $handshakes -gt 0 ]]; then
        echo >> "$OUTPUT_DIR/summary_report.txt"
        echo "📡 INFO: Handshake frames captured. Possible credential harvesting." >> "$OUTPUT_DIR/summary_report.txt"
    fi
    
    # Display summary
    cat "$OUTPUT_DIR/summary_report.txt" | tee -a "$LOGFILE"
    
    # Final status
    echo >> "$OUTPUT_DIR/summary_report.txt"
    echo "Analysis completed at: $(date)" >> "$OUTPUT_DIR/summary_report.txt"
    echo "Evidence preserved for legal proceedings." >> "$OUTPUT_DIR/summary_report.txt"
}

# Main execution
main() {
    log_event "Starting WiFi attack detection suite"
    
    # Check prerequisites
    check_monitor_mode
    
    # Run detection modules in parallel
    log_event "Starting parallel detection modules..."
    
    # Start background processes
    detect_rogue_aps &
    PID1=$!
    
    monitor_handshakes &
    PID2=$!
    
    monitor_deauth_attacks &
    PID3=$!
    
    analyze_network_changes &
    PID4=$!
    
    monitor_dhcp_activity &
    PID5=$!
    
    # Wait for all processes to complete
    wait $PID1 $PID2 $PID3 $PID4 $PID5
    
    # Generate final report
    generate_report
    
    log_event "Detection suite completed"
    echo
    echo "🎯 Results saved to: $OUTPUT_DIR"
    echo "📋 Log file: $LOGFILE"
    echo "📊 Summary: $OUTPUT_DIR/summary_report.txt"
    
    # Final threat assessment display
    if [[ -f "$OUTPUT_DIR/summary_report.txt" ]]; then
        echo
        echo "=== FINAL THREAT ASSESSMENT ==="
        grep "Threat Level:" "$OUTPUT_DIR/summary_report.txt"
        grep "🚨\|⚠️\|📡" "$OUTPUT_DIR/summary_report.txt" 2>/dev/null || echo "No critical alerts."
    fi
}

# Cleanup function
cleanup() {
    log_event "Cleaning up processes..."
    # Kill any remaining background processes
    jobs -p | xargs -r kill 2>/dev/null
    killall airodump-ng tshark 2>/dev/null
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Run main function
main "$@"