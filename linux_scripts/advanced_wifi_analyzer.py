#!/usr/bin/env python3
"""
Advanced WiFi Attack Analysis
Correlates deauth attacks with subsequent data collection attempts
"""

import subprocess
import time
import json
import pandas as pd
from datetime import datetime, timedelta
import threading
import queue
import signal
import sys

# Main Analyzer Class
class WiFiAttackAnalyzer:
    def __init__(self, interface="mon0"):
        self.interface = interface
        self.running = False
        self.events = queue.Queue()
        self.networks_baseline = {}
        self.handshake_events = []
        self.deauth_events = []
        self.rogue_aps = []

    # Main monitoring function    
    def start_monitoring(self, duration=300):  # 5 minutes default/Change as needed
        """Start comprehensive WiFi attack monitoring"""
        print(f"[+] Starting WiFi attack analysis on {self.interface}")
        print(f"[+] Monitoring for {duration} seconds...")
        
        self.running = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_deauth_attacks),
            threading.Thread(target=self.monitor_handshakes),
            threading.Thread(target=self.monitor_new_networks),
            threading.Thread(target=self.monitor_probe_responses),
            threading.Thread(target=self.analyze_correlations)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Run for specified duration
        time.sleep(duration)
        self.running = False
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=2)
        
        self.generate_analysis_report()
    
    # Monitor functions
    def monitor_deauth_attacks(self):
        """Monitor deauthentication attacks in real-time"""
        cmd = [
            "tshark", "-i", self.interface,
            "-f", "wlan type mgt subtype deauth",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da", 
            "-e", "wlan.bssid",
            "-e", "wlan.fixed.reason_code"
        ]
        # Monitor deauth attacks
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.DEVNULL, text=True)
            
            while self.running:
                line = process.stdout.readline()
                if line:
                    fields = line.strip().split('\t')
                    if len(fields) >= 5:
                        event = {
                            'type': 'deauth',
                            'timestamp': float(fields[0]),
                            'source_mac': fields[1],
                            'dest_mac': fields[2],
                            'bssid': fields[3],
                            'reason_code': fields[4],
                            'is_spoofed': fields[1] == fields[2] == fields[3],
                            'is_malicious': fields[4] == '0'
                        }
                        self.deauth_events.append(event)
                        self.events.put(event)
                        
                        if event['is_spoofed'] or event['is_malicious']:
                            print(f"[!] ATTACK: Deauth on {event['bssid']} "
                                  f"(Spoofed: {event['is_spoofed']}, "
                                  f"Malicious: {event['is_malicious']})")
            
            process.terminate()
        except Exception as e:
            print(f"[-] Error monitoring deauth: {e}")
    
    # Monitor handshake captures
    def monitor_handshakes(self):
        """Monitor WPA handshake capture attempts"""
        cmd = [
            "tshark", "-i", self.interface,
            "-f", "ether proto 0x888e",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "eapol.type"
        ]
        # Monitor handshake captures
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
            
            while self.running:
                line = process.stdout.readline()
                if line:
                    fields = line.strip().split('\t')
                    if len(fields) >= 5:
                        event = {
                            'type': 'handshake',
                            'timestamp': float(fields[0]),
                            'source_mac': fields[1],
                            'dest_mac': fields[2],
                            'bssid': fields[3],
                            'eapol_type': fields[4]
                        }
                        self.handshake_events.append(event)
                        self.events.put(event)
                        
                        print(f"[*] HANDSHAKE: {event['bssid']} - Type {event['eapol_type']}")
            
            process.terminate()
        except Exception as e:
            print(f"[-] Error monitoring handshakes: {e}")
    
    # Monitor new networks (evil twins)
    def monitor_new_networks(self):
        """Monitor for new networks appearing (potential evil twins)"""
        baseline_established = False
        # Initial baseline scan
        while self.running:
            try:
                # Scan for networks every 30 seconds
                cmd = ["airodump-ng", "--write", "/path/to/output/scan", "--write-interval", "1", # Adjust path as needed
                       "--output-format", "csv", self.interface]
                
                process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                time.sleep(30)
                process.terminate()
                
                # Parse results
                try:
                    df = pd.read_csv("/path/to/output/scan-01.csv", skiprows=1)  # Adjust path as needed
                    current_networks = {}
                    
                    for _, row in df.iterrows():
                        if pd.notna(row.get('ESSID')):
                            bssid = row['BSSID'].strip()
                            essid = row['ESSID'].strip()
                            channel = row['channel'].strip() if pd.notna(row.get('channel')) else 'Unknown'
                            
                            current_networks[bssid] = {
                                'essid': essid,
                                'channel': channel,
                                'first_seen': time.time()
                            }
                    
                    if not baseline_established:
                        self.networks_baseline = current_networks.copy()
                        baseline_established = True
                        print(f"[+] Baseline established with {len(self.networks_baseline)} networks")
                    else:
                        # Check for new networks
                        for bssid, info in current_networks.items():
                            if bssid not in self.networks_baseline:
                                # Check if SSID already exists with different BSSID
                                is_evil_twin = any(
                                    baseline_info['essid'] == info['essid'] 
                                    for baseline_info in self.networks_baseline.values()
                                )
                                
                                event = {
                                    'type': 'new_network',
                                    'timestamp': time.time(),
                                    'bssid': bssid,
                                    'essid': info['essid'],
                                    'channel': info['channel'],
                                    'is_evil_twin': is_evil_twin
                                }
                                
                                self.events.put(event)
                                
                                if is_evil_twin:
                                    self.rogue_aps.append(event)
                                    print(f"[!] EVIL TWIN DETECTED: {info['essid']} ({bssid}) on channel {info['channel']}")
                                else:
                                    print(f"[*] NEW NETWORK: {info['essid']} ({bssid}) on channel {info['channel']}")
                
                except Exception as e:
                    print(f"[-] Error parsing scan results: {e}")
                
            except Exception as e:
                print(f"[-] Error in network monitoring: {e}")
    
    # Monitor probe responses
    def monitor_probe_responses(self):
        """Monitor probe responses for reconnaissance detection"""
        cmd = [
            "tshark", "-i", self.interface,
            "-f", "wlan type mgt subtype probe-resp",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan_mgt.ssid"
        ]
        # Monitor probe responses
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
            
            probe_counts = {}
            
            while self.running:
                line = process.stdout.readline()
                if line:
                    fields = line.strip().split('\t')
                    if len(fields) >= 4:
                        src_mac = fields[1]
                        ssid = fields[3] if len(fields) > 3 else ""
                        
                        if src_mac not in probe_counts:
                            probe_counts[src_mac] = 0
                        probe_counts[src_mac] += 1
                        
                        # Alert on excessive probing (reconnaissance)
                        if probe_counts[src_mac] > 50:  # Threshold
                            event = {
                                'type': 'excessive_probing',
                                'timestamp': float(fields[0]),
                                'source_mac': src_mac,
                                'probe_count': probe_counts[src_mac],
                                'ssid': ssid
                            }
                            self.events.put(event)
                            print(f"[!] RECONNAISSANCE: {src_mac} excessive probing ({probe_counts[src_mac]} probes)")
            
            process.terminate()
        except Exception as e:
            print(f"[-] Error monitoring probe responses: {e}")
    
    # Correlation analysis
    def analyze_correlations(self):
        """Analyze correlations between deauth attacks and data collection"""
        attack_window = 60  # seconds after deauth to look for collection attempts
        
        while self.running:
            time.sleep(10)  # Check every 10 seconds
            
            current_time = time.time()
            
            # Look for patterns: deauth followed by handshake captures
            for deauth in self.deauth_events:
                if current_time - deauth['timestamp'] > attack_window:
                    continue
                
                # Find handshakes within attack window
                related_handshakes = [
                    hs for hs in self.handshake_events
                    if (hs['bssid'] == deauth['bssid'] and
                        deauth['timestamp'] < hs['timestamp'] < deauth['timestamp'] + attack_window)
                ]
                
                if related_handshakes:
                    print(f"[!] CORRELATION: Deauth on {deauth['bssid']} followed by "
                          f"{len(related_handshakes)} handshake captures")
                
                # Find evil twins appearing after deauth
                related_twins = [
                    ap for ap in self.rogue_aps
                    if (ap['is_evil_twin'] and
                        deauth['timestamp'] < ap['timestamp'] < deauth['timestamp'] + attack_window)
                ]
                
                if related_twins:
                    for twin in related_twins:
                        print(f"[!] CORRELATION: Deauth followed by evil twin {twin['essid']} ({twin['bssid']})")
    
    # Generate analysis report
    def generate_analysis_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "="*60)
        print("WiFi ATTACK ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nMONITORING SUMMARY:")
        print(f"  Deauth Events: {len(self.deauth_events)}")
        print(f"  Handshake Events: {len(self.handshake_events)}")
        print(f"  Rogue APs Detected: {len(self.rogue_aps)}")
        
        # Analyze attack patterns
        spoofed_attacks = [d for d in self.deauth_events if d['is_spoofed']]
        malicious_attacks = [d for d in self.deauth_events if d['is_malicious']]
        
        print(f"\nATTACK ANALYSIS:")
        print(f"  Spoofed Deauth Attacks: {len(spoofed_attacks)}")
        print(f"  Malicious Deauth (Code 0): {len(malicious_attacks)}")
        
        # Target analysis
        targets = {}
        for deauth in self.deauth_events:
            bssid = deauth['bssid']
            if bssid not in targets:
                targets[bssid] = 0
            targets[bssid] += 1
        
        if targets:
            print(f"\nTOP TARGETS:")
            sorted_targets = sorted(targets.items(), key=lambda x: x[1], reverse=True)
            for bssid, count in sorted_targets[:5]:
                print(f"  {bssid}: {count} attacks")
        
        # Data collection indicators
        collection_indicators = 0
        if self.handshake_events:
            collection_indicators += 1
            print(f"\n[!] HANDSHAKE CAPTURE DETECTED: {len(self.handshake_events)} events")
        
        if self.rogue_aps:
            collection_indicators += 1
            print(f"[!] EVIL TWIN APs DETECTED: {len(self.rogue_aps)} rogue networks")
        
        if collection_indicators == 0:
            print(f"\n[+] NO DATA COLLECTION INDICATORS DETECTED")
        
        # Risk assessment
        risk_score = len(spoofed_attacks) + len(malicious_attacks) + len(self.rogue_aps) * 2
        if risk_score > 20:
            risk_level = "CRITICAL"
        elif risk_score > 10:
            risk_level = "HIGH"
        elif risk_score > 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        print(f"\nRISK ASSESSMENT: {risk_level}")
        print(f"Risk Score: {risk_score}")
        
        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'deauth_events': len(self.deauth_events),
            'handshake_events': len(self.handshake_events),
            'rogue_aps': len(self.rogue_aps),
            'spoofed_attacks': len(spoofed_attacks),
            'malicious_attacks': len(malicious_attacks),
            'risk_level': risk_level,
            'risk_score': risk_score,
            'targets': targets
        }
        
        with open('/output/to/path/attack_analysis_report.json', 'w') as f: # Adjust path as needed
            json.dump(report_data, f, indent=2)
        
        print(f"\nDetailed report saved to: /output/to/path/attack_analysis_report.json") # Adjust path as needed

# Signal handler for graceful exit
def signal_handler(sig, frame):
    print('\n[!] Monitoring interrupted by user')
    sys.exit(0)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='WiFi Attack Analysis Tool')
    parser.add_argument('-i', '--interface', default='mon0', 
                       help='Monitor mode interface (default: mon0)')
    parser.add_argument('-t', '--time', type=int, default=300,
                       help='Monitoring duration in seconds (default: 300)')
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    analyzer = WiFiAttackAnalyzer(interface=args.interface)
    try:
        analyzer.start_monitoring(duration=args.time)
    except KeyboardInterrupt:
        print('\n[!] Monitoring interrupted')
    except Exception as e:
        print(f'[-] Error: {e}')