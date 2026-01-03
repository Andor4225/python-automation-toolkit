#!/usr/bin/env python3
"""
Analyzer Output Diagnosis Script
Compares expected frame processing results with actual analyzer JSON output
"""

import json
import os
from pathlib import Path
from collections import defaultdict, Counter

class AnalyzerOutputDiagnostics:
    def __init__(self):
        self.pcap_dir = r"C:\Users\Gavin\Desktop\WiFI_BT pcaps"
        self.output_dir = r"C:\Users\Gavin\Desktop\WiFi & BT Analysis"
        self.json_file = Path(self.output_dir) / "pcap_analysis.json"
        
    def diagnose_analyzer_output(self):
        """Diagnose the actual analyzer output vs expected results"""
        print(f"🔍 ANALYZER OUTPUT DIAGNOSIS")
        print("=" * 60)
        print(f"📁 PCAP Directory: {self.pcap_dir}")
        print(f"📁 Output Directory: {self.output_dir}")
        print(f"📄 JSON File: {self.json_file}")
        
        # Check if output file exists
        if not self.json_file.exists():
            print(f"❌ JSON output file not found!")
            print(f"💡 Run your analyzer first to generate: {self.json_file}")
            return
        
        try:
            with open(self.json_file, 'r') as f:
                data = json.load(f)
            print(f"✅ Loaded analyzer output: {self.json_file}")
        except json.JSONDecodeError as e:
            print(f"❌ JSON decoding error: {e}")
        except FileNotFoundError as e:
            print(f"❌ File not found: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            
        # Load and analyze the JSON output
        try:
            with open(self.json_file, 'r') as f:
                data = json.load(f)
            print(f"✅ Loaded analyzer output: {self.json_file}")
            
            # Analyze the results
            self.debug_json_structure(data)
            self._analyze_wifi_results(data)
            self._analyze_security_events(data)
            self._analyze_file_processing(data)
            self._compare_with_expected(data)
            
        except Exception as e:
            print(f"❌ Error loading JSON: {e}")
    
    def _analyze_wifi_results(self, data):
        """Analyze WiFi results in detail - FIXED VERSION"""
        print(f"\n📡 WIFI RESULTS ANALYSIS")
        print("-" * 40)
    
        wifi_results = data.get('wifi_results', [])
        print(f"WiFi result entries: {len(wifi_results)}")
    
        if not wifi_results:
            print(f"❌ No WiFi results found in output!")
            return
    
        for i, result in enumerate(wifi_results):
            file_path = result.get('file_path', 'Unknown')
            filename = Path(file_path).name if file_path != 'Unknown' else 'Unknown'
        
            # ORIGINAL LOCATION (summaries only)
            devices = result.get('devices', {})
            security_events = result.get('security_events', [])
            packet_count = result.get('packet_count', 0)
        
            # NEW: CHECK DETAILED ANALYSIS SECTION
            detailed_devices = {}
            detailed_security_count = 0
        
            if 'detailed_analysis' in data:
                detailed_analysis = data['detailed_analysis']
                detailed_devices = detailed_analysis.get('wifi_devices', {})
            
                # Count security events from detailed devices
                for device in detailed_devices.values():
                    detailed_security_count += len(device.get('security_events', []))
        
            # Use detailed data if available, otherwise use summary
            final_devices = detailed_devices if detailed_devices else devices
            final_security_count = detailed_security_count if detailed_security_count > 0 else len(security_events)
        
            print(f"\n  📄 Entry {i+1}: {filename}")
            print(f"     Device count (summary): {len(devices)}")
            print(f"     Device count (detailed): {len(detailed_devices)}")
            print(f"     📍 Using: {len(final_devices)} devices from {'detailed_analysis' if detailed_devices else 'summary'}")
            print(f"     Security events: {final_security_count}")
            print(f"     Packet count: {packet_count}")
        
            # Analyze devices in detail
            if final_devices:
                print(f"     📱 Device breakdown:")
                for j, (mac, device) in enumerate(list(final_devices.items())[:3]):  # Show first 3
                    frame_types = device.get('frame_types', [])
                    rssi_stats = device.get('rssi_statistics', {})
                    rssi_count = rssi_stats.get('count', 0) if rssi_stats else len(device.get('rssi_readings', []))
                
                    # Handle different security event formats
                    device_security_events = len(device.get('security_events', []))
                
                    print(f"       {j+1}. {mac}")
                    print(f"          Packets: {device.get('packet_count', 'N/A')}")
                    print(f"          RSSI readings: {rssi_count}")
                    print(f"          Security events: {device_security_events}")
                
                    if isinstance(frame_types, list) and frame_types:
                        frame_summary = Counter(frame_types)
                        print(f"          Frame types: {dict(list(frame_summary.items())[:3])}")
            
                if len(final_devices) > 3:
                    print(f"       ... and {len(final_devices) - 3} more devices")
            else:
                print(f"     ❌ NO DEVICES FOUND!")
            
            # Check for specific issues with the corrected data
            self._check_file_specific_issues(filename, {
                'devices': final_devices,
                'security_events': [],  # We'll use device-level events
                'packet_count': packet_count
            })
    
    def _check_file_specific_issues(self, filename, result):
        """Check for issues specific to each file type"""
        devices = result.get('devices', {})
        device_count = len(devices)
        
        if 'rssi' in filename.lower():
            print(f"     🎯 RSSI File Analysis:")
            if device_count == 0:
                print(f"       ❌ CRITICAL: RSSI file shows 0 devices (expected ~20)")
            elif device_count < 15:
                print(f"       ⚠️  LOW: Only {device_count} devices (expected ~20)")
            else:
                print(f"       ✅ Good device count: {device_count}")
                
            # Check for RSSI data
            rssi_devices = 0
            total_rssi = 0
            for device in devices.values():
                rssi_readings = device.get('rssi_readings', [])
                if rssi_readings:
                    rssi_devices += 1
                    total_rssi += len(rssi_readings)
            
            print(f"       RSSI data: {rssi_devices}/{device_count} devices have RSSI")
            print(f"       Total RSSI readings: {total_rssi}")
                
        elif 'raw' in filename.lower():
            print(f"     🎯 RAW File Analysis:")
            if device_count == 0:
                print(f"       ❌ CRITICAL: RAW file shows 0 devices (expected ~22)")
            elif device_count < 15:
                print(f"       ⚠️  LOW: Only {device_count} devices (expected ~22)")
            else:
                print(f"       ✅ Good device count: {device_count}")
                
            # Check for deauth frames specifically
            deauth_found = False
            for device in devices.values():
                frame_types = device.get('frame_types', [])
                if isinstance(frame_types, list):
                    for frame_type in frame_types:
                        if 'deauth' in str(frame_type).lower() or '12' in str(frame_type):
                            deauth_found = True
                            break
            
            print(f"       Deauth frames found: {'✅ Yes' if deauth_found else '❌ No (but diagnosis found 0, so this is correct)'}")
    
    def _analyze_security_events(self, data):
        """Analyze security event detection"""
        print(f"\n🚨 SECURITY EVENTS ANALYSIS")
        print("-" * 40)
        
        total_security_events = 0
        event_types = Counter()
        
        wifi_results = data.get('wifi_results', [])
        for result in wifi_results:
            # Check file-level security events
            file_events = result.get('security_events', [])
            total_security_events += len(file_events)
            
            for event in file_events:
                event_type = event.get('type', 'unknown')
                event_types[event_type] += 1
            
            # Check device-level security events - USE detailed_analysis
            if 'detailed_analysis' in data:
                devices = data['detailed_analysis'].get('wifi_devices', {})
            else:
                devices = result.get('devices', {})
    
            for device in devices.values():
                device_events = device.get('security_events', [])
                total_security_events += len(device_events)
                
                for event in device_events:
                    event_type = event.get('type', 'unknown')
                    event_types[event_type] += 1
        
        print(f"Total security events: {total_security_events}")
        
        if event_types:
            print(f"Event breakdown:")
            for event_type, count in event_types.most_common():
                print(f"  {event_type}: {count}")
        else:
            print(f"❌ NO SECURITY EVENTS DETECTED")
            print(f"💡 This is the main issue - events should be detected from deauth frames")
    
    def _analyze_file_processing(self, data):
        """Analyze which files were processed"""
        print(f"\n📂 FILE PROCESSING ANALYSIS")
        print("-" * 40)
        
        wifi_results = data.get('wifi_results', [])
        bluetooth_results = data.get('bluetooth_results', [])
        network_results = data.get('network_results', [])
        
        print(f"File processing summary:")
        print(f"  WiFi files processed: {len(wifi_results)}")
        print(f"  Bluetooth files processed: {len(bluetooth_results)}")
        print(f"  Network files processed: {len(network_results)}")
        
        # Check which specific files were processed
        processed_files = []
        for result in wifi_results:
            file_path = result.get('file_path', '')
            if file_path:
                processed_files.append(Path(file_path).name)
        
        print(f"\nWiFi files processed:")
        for filename in processed_files:
            print(f"  - {filename}")
        
        # Check for expected files
        expected_files = ['rssi3.pcap', 'raw_9.pcap']
        missing_files = [f for f in expected_files if f not in processed_files]
        
        if missing_files:
            print(f"\n⚠️  Expected files not processed: {missing_files}")
    
    def _compare_with_expected(self, data):
        """Compare with expected results from diagnosis"""
        print(f"\n🔄 EXPECTED vs ACTUAL COMPARISON")
        print("-" * 40)
        
        # Expected results from our frame diagnosis
        expected_results = {
            'rssi3.pcap': {
                'devices': 20,
                'deauth_frames': 11,
                'management_frames': 962
            },
            'raw_9.pcap': {
                'devices': 22,
                'deauth_frames': 0,
                'management_frames': 980
            }
        }
        
        wifi_results = data.get('wifi_results', [])
        
        for result in wifi_results:
            file_path = result.get('file_path', '')
            filename = Path(file_path).name if file_path else 'Unknown'
            
            if filename in expected_results:
                expected = expected_results[filename]
                actual_devices = len(result.get('devices', {}))
                
                print(f"\n📄 {filename}:")
                print(f"  Expected devices: {expected['devices']}")
                print(f"  Actual devices: {actual_devices}")
                
                if actual_devices == 0 and expected['devices'] > 0:
                    print(f"  ❌ CRITICAL DISCONNECT: Expected {expected['devices']}, got 0")
                    print(f"     This indicates a bug in device serialization or filtering")
                elif actual_devices < expected['devices'] * 0.5:
                    print(f"  ⚠️  SIGNIFICANT GAP: Expected {expected['devices']}, got {actual_devices}")
                else:
                    print(f"  ✅ Device count roughly matches")
                
                # Check for deauth events if expected
                if expected['deauth_frames'] > 0:
                    security_events = len(result.get('security_events', []))
                    device_security_events = sum(
                        len(device.get('security_events', [])) 
                        for device in result.get('devices', {}).values()
                    )
                    total_events = security_events + device_security_events
                    
                    print(f"  Expected deauth potential: {expected['deauth_frames']} frames")
                    print(f"  Actual security events: {total_events}")
                    
                    if expected['deauth_frames'] > 0 and total_events == 0:
                        print(f"  ❌ SECURITY DETECTION BROKEN: {expected['deauth_frames']} deauth frames not converted to events")

    def debug_json_structure(self, data):
        """Debug the JSON structure to understand data layout"""
        print(f"\n🔍 JSON STRUCTURE DEBUG:")
        print(f"   Top-level keys: {list(data.keys())}")
    
        if 'detailed_analysis' in data:
            detailed = data['detailed_analysis']
            print(f"   detailed_analysis keys: {list(detailed.keys())}")
        
            if 'wifi_devices' in detailed:
                wifi_devices = detailed['wifi_devices']
                print(f"   wifi_devices count: {len(wifi_devices)}")
                if wifi_devices:
                    sample_device = list(wifi_devices.values())[0]
                    print(f"   Sample device keys: {list(sample_device.keys())}")
    
    def _suggest_fixes(self):
        """Suggest specific fixes based on findings"""
        print(f"\n💡 SUGGESTED INVESTIGATION STEPS")
        print("-" * 40)
        print(f"1. Check device creation logic in _process_packet")
        print(f"2. Verify device dictionary isn't being cleared somewhere")
        print(f"3. Check if post-processing is removing devices")
        print(f"4. Verify JSON serialization isn't dropping devices")
        print(f"5. Check for exceptions that might be clearing device data")

def main():
    """Main analyzer output diagnosis"""
    diagnostics = AnalyzerOutputDiagnostics()
    diagnostics.diagnose_analyzer_output()
    diagnostics._suggest_fixes()

if __name__ == "__main__":
    main()