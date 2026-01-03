import os
import json
import time
import threading
import queue
import logging
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import asdict
from watchdog.observers import Observer
from adapter_interfaces import RSSTTriangulationEngine
# Import your custom modules
from data_model import AnalysisResult, SecurityEvent
from adapter_interfaces import AdapterFactory
from file_watcher import PcapFileHandler
import math
from dataclasses import dataclass
import glob
import pyshark

# =============================================================================
# MAIN ANALYZER ORCHESTRATOR
# =============================================================================

from venv import logger

# DIRECT PCAP TRIANGULATION - ADD THIS TO YOUR main_orchestrator.py

import math
import pyshark
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import os

@dataclass
class CapturePosition:
    """Represents a capture position with coordinates"""
    name: str
    x: float
    y: float
    pcap_file_path: str

@dataclass
class DeviceRSSI:
    """RSSI measurement from a specific position"""
    position: CapturePosition
    rssi: float
    distance_estimate: float

@dataclass
class TriangulationResult:
    """Result of triangulation calculation"""
    mac_address: str
    calculated_position: Tuple[float, float]
    confidence_score: float
    position_measurements: List[DeviceRSSI]
    error_analysis: Dict

class TriangulationEngine:
    """Triangulation engine that reads PCAP files directly"""
    
    def __init__(self, pcap_directory: str, user_mac_address: str = None, packet_limit: int = None): # <---- Change to process more RSSI packets ---
        self.pcap_directory = pcap_directory
        self.user_mac_address = user_mac_address.lower() if user_mac_address else None
        self.packet_limit = packet_limit

        # RSSI to distance conversion parameters
        self.rssi_distance_map = {
            (-30, float('inf')): 3.0,   # Very close
            (-40, -30): 10.0,           # Close  
            (-50, -40): 25.0,           # Moderate
            (-60, -50): 50.0,           # Far
            (-70, -60): 100.0,          # Very far
            (-80, -70): 150.0,          # Distant
            (float('-inf'), -80): 200.0 # Very distant
        }

    def analyze_device_proximity(self, device_data: Dict) -> Dict:
        """Analyze proximity for a single device"""
        rssi_stats = device_data.get('rssi_statistics', {})
    
        if not rssi_stats or rssi_stats.get('count', 0) == 0:
            return self._create_empty_proximity_analysis()
    
        # Extract RSSI data
        avg_rssi = rssi_stats.get('avg', -100)
        max_rssi = rssi_stats.get('max', -100)
        min_rssi = rssi_stats.get('min', -100)
    
        # Calculate distance estimates using existing rssi_to_distance method
        avg_distance = self.rssi_to_distance(avg_rssi)
        closest_distance = self.rssi_to_distance(max_rssi)
        farthest_distance = self.rssi_to_distance(min_rssi)
    
        # Determine proximity zone
        proximity_zone = self._classify_proximity_zone(closest_distance)
    
        # Calculate threat proximity score
        threat_score = self._calculate_threat_proximity_score(closest_distance, avg_distance, device_data)
    
        return {
            'distance_analysis': {
                'avg_distance_ft': round(avg_distance, 1),
                'closest_distance_ft': round(closest_distance, 1),
                'farthest_distance_ft': round(farthest_distance, 1),
                'distance_variation_ft': round(farthest_distance - closest_distance, 1)
            },
            'proximity_classification': {
                'zone': proximity_zone,
                'threat_proximity_score': threat_score,
                'risk_level': self._get_proximity_risk_level(threat_score),
                'location_estimate': self._estimate_location(proximity_zone, closest_distance)
            },
            'signal_intelligence': {
                'signal_strength_category': self._categorize_signal_strength(max_rssi),
                'signal_consistency': self._analyze_signal_consistency(rssi_stats),
                'movement_detected': farthest_distance - closest_distance > 10
            }
        }
    
    def _classify_proximity_zone(self, distance: float) -> str:
        """Classify distance into proximity zones"""
        proximity_zones = {
            'immediate': 5,     # Same room
            'close': 15,        # Adjacent room  
            'neighbor_close': 25, # Close neighbor
            'neighbor_far': 40,   # Far neighbor
            'distant': 100       # Street/beyond
        }
    
        for zone, max_distance in proximity_zones.items():
            if distance <= max_distance:
                return zone
        return '    distant'

    def _calculate_threat_proximity_score(self, closest_dist: float, avg_dist: float, device_data: Dict) -> int:
        """Calculate threat proximity score (0-100) - EXCLUDE YOUR ROUTER"""
        # Check if this is your router - exclude from threat scoring
        mac_address = device_data.get('mac_address', '')
        if mac_address.lower() == '<ROUTER_MAC_ADDRESS>':  # Your router MAC <---- Change to your router MAC ----
            return 0  # Your router is not a threat
    
        base_score = 0
    
        # Distance component (closer = higher score)
        if closest_dist <= 5:
            base_score += 40  # Same room
        elif closest_dist <= 15:
            base_score += 30  # Adjacent room
        elif closest_dist <= 25:
            base_score += 20  # Close neighbor
        elif closest_dist <= 40:
            base_score += 10  # Far neighbor
    
        # Security events multiplier
        security_events = device_data.get('security_events', [])
        if security_events:
            event_multiplier = min(len(security_events) / 10, 3.0)
            base_score += 20 * event_multiplier
    
        return min(int(base_score), 100)

    def _get_proximity_risk_level(self, threat_score: int) -> str:
        """Convert threat score to risk level"""
        if threat_score >= 70:
            return 'CRITICAL'
        elif threat_score >= 50:
            return 'HIGH'
        elif threat_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _estimate_location(self, zone: str, distance: float) -> str:
        """Estimate likely location based on proximity zone"""
        location_estimates = {
            'immediate': f'Same room (~{distance:.0f}ft)',
            'close': f'Adjacent room/area (~{distance:.0f}ft)',
            'neighbor_close': f'Close neighbor property (~{distance:.0f}ft)',
            'neighbor_far': f'Neighbor property (~{distance:.0f}ft)',
            'distant': f'Street/distant location (~{distance:.0f}ft)'
        }
        return location_estimates.get(zone, f'Unknown location (~{distance:.0f}ft)')

    def _categorize_signal_strength(self, rssi: float) -> str:
        """Categorize signal strength"""
        if rssi > -40:
            return 'Very Strong (very close)'
        elif rssi > -60:
            return 'Strong (close)'
        elif rssi > -70:
            return 'Good (moderate distance)'
        elif rssi > -80:
            return 'Fair (far)'
        else:
            return 'Weak (very far)'

    def _analyze_signal_consistency(self, rssi_stats: Dict) -> str:
        """Analyze signal consistency"""
        std_dev = rssi_stats.get('std_dev', 0)
        if std_dev < 3:
            return 'Very Consistent (stationary/stable)'
        elif std_dev < 7:
            return 'Consistent (mostly stationary)'
        elif std_dev < 15:
            return 'Variable (some movement)'
        else:
            return 'Highly Variable (mobile/moving)'

    def _create_empty_proximity_analysis(self) -> Dict:
        """Return empty analysis for devices without RSSI data"""
        return {
            'distance_analysis': {
                'avg_distance_ft': None,
                'closest_distance_ft': None,
                'farthest_distance_ft': None,
                'distance_variation_ft': None
            },
            'proximity_classification': {
                'zone': 'unknown',
                'threat_proximity_score': 0,
                'risk_level': 'LOW',
                'location_estimate': 'No signal data available'
            },
            'signal_intelligence': {
                'signal_strength_category': 'No signal detected',
                'signal_consistency': 'Unknown',
                'movement_detected': False
            }
        }
    
    def detect_rssi_pcap_files(self) -> List[CapturePosition]:
        """Detect rssi*.pcap files directly (any number)"""
        positions = []
    
        # Look for any rssi*.pcap files in directory
        import glob
        rssi_pattern = os.path.join(self.pcap_directory, "rssi*.pcap")
        rssi_files = glob.glob(rssi_pattern)
    
        if not rssi_files:
            print(f"   ❌ No rssi*.pcap files found in {self.pcap_directory}")
            return positions
    
        # Sort files to ensure consistent ordering
        rssi_files.sort()
    
        for pcap_file in rssi_files:
            # Extract number from filename (e.g., rssi4.pcap -> 4)
            filename = os.path.basename(pcap_file)
            try:
                # Extract number after 'rssi' and before '.pcap'
                number_str = filename.replace('rssi', '').replace('.pcap', '')
                file_number = int(number_str)
            except ValueError:
                print(f"   ⚠️  Skipping invalid filename: {filename}")
                continue
        
            print(f"   ✅ Found PCAP: {pcap_file}")
        
            # <<<< ----- Default position coordinates (you can customize these) ----- >>>>
            if file_number == 1:
                x, y = 0.0, 0.0      # Reference point
            elif file_number == 2:
                x, y = 37.0, 0.0     # 37ft from router
            elif file_number == 3:
                x, y = 22.0, 0.0     # 22ft from router
            else:
                # For rssi4, rssi5, etc. - spread them out automatically
                x, y = file_number * 15.0, 0.0  # 15ft intervals
                print(f"   🔧 Auto-positioning rssi{file_number} at ({x}ft, {y}ft)")
        
            position = CapturePosition(f"rssi{file_number}", x, y, pcap_file)
            positions.append(position)
    
        print(f"   📊 Total PCAP files detected: {len(positions)}")
        return positions
    
    def rssi_to_distance(self, rssi: float) -> float:
        """Convert RSSI to distance in feet using realistic ranges"""
        for (min_rssi, max_rssi), distance in self.rssi_distance_map.items():
            if min_rssi <= rssi < max_rssi:
                return distance
        return 200.0  # Default fallback
    
    def extract_rssi_from_pcap(self, pcap_file: str, position: CapturePosition) -> Dict[str, float]:
        """Extract RSSI data directly from PCAP file"""
        device_rssi = {}
        packet_count = 0 # < ---- Set to 0 to analyze all packets
    
        print(f"   📡 Analyzing {position.name}: {os.path.basename(pcap_file)}")
    
        try:
            # Read PCAP file with PyShark
            capture = pyshark.FileCapture(pcap_file, display_filter='wlan')
        
            for packet in capture:
                packet_count += 1
                # Add packet limit for testing
                # if self.packet_limit and packet_count > self.packet_limit:
                #    print(f"   🐛 DEBUG: Stopping at {self.packet_limit} packets for triangulation testing")
                #    break
                try:
                    # Extract source MAC address
                    if hasattr(packet, 'wlan') and hasattr(packet.wlan, 'sa'):
                        src_mac = packet.wlan.sa.lower()
                    
                        # Extract RSSI from radiotap header
                        rssi_value = None
                    
                        if hasattr(packet, 'radiotap'):
                            # Try multiple RSSI field names
                            rssi_fields = ['dbm_antsignal', 'signal_dbm', 'signal_quality']
                        
                            for field in rssi_fields:
                                if hasattr(packet.radiotap, field):
                                    try:
                                        rssi_value = int(getattr(packet.radiotap, field))
                                        break
                                    except:
                                        continue
                    
                        # Alternative: check wlan_radio
                        if rssi_value is None and hasattr(packet, 'wlan_radio'):
                            if hasattr(packet.wlan_radio, 'signal_dbm'):
                                try:
                                    rssi_value = int(packet.wlan_radio.signal_dbm)
                                except:
                                    pass
                    
                        # Store RSSI data
                        if rssi_value is not None and src_mac:
                            if src_mac not in device_rssi:
                                device_rssi[src_mac] = []
                            device_rssi[src_mac].append(rssi_value)
                        
                except Exception as e:
                    continue  # Skip bad packets, keep processing
        
            capture.close()
        
        except Exception as e:
            print(f"   ⚠️  PCAP file corrupted but partially processed: {os.path.basename(pcap_file)}")
            print(f"   📊 Successfully processed {packet_count} packets before error")
            print(f"   🔄 Continuing with available data...")
            # Don't return {} - continue to process what we have
    
        # Calculate average RSSI for each device
        device_avg_rssi = {}
        for mac, rssi_list in device_rssi.items():
            if rssi_list:
                avg_rssi = sum(rssi_list) / len(rssi_list)
                device_avg_rssi[mac] = avg_rssi
    
        print(f"   📊 {position.name}: {packet_count} packets, {len(device_avg_rssi)} devices with RSSI")
    
        return device_avg_rssi
    
    def extract_device_measurements_from_pcaps(self, positions: List[CapturePosition]) -> Dict[str, List[DeviceRSSI]]:
        """Extract RSSI measurements for each device across PCAP files"""
        device_measurements = {}
        
        for position in positions:
            # Extract RSSI data from this PCAP file
            device_rssi_data = self.extract_rssi_from_pcap(position.pcap_file_path, position)
            
            # Convert to DeviceRSSI objects
            for mac_address, avg_rssi in device_rssi_data.items():
                distance_est = self.rssi_to_distance(avg_rssi)
                
                measurement = DeviceRSSI(
                    position=position,
                    rssi=avg_rssi,
                    distance_estimate=distance_est
                )
                
                if mac_address not in device_measurements:
                    device_measurements[mac_address] = []
                device_measurements[mac_address].append(measurement)
        
        return device_measurements
    
    def calculate_circle_intersection(self, x1: float, y1: float, r1: float, 
                                    x2: float, y2: float, r2: float) -> List[Tuple[float, float]]:
        """Calculate intersection points of two circles"""
        # Distance between circle centers
        d = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
        
        # Handle edge cases
        if d == 0 and r1 == r2:
            return [(x1, y1)]
        
        if d == 0:
            return []
        
        # Check if circles can intersect
        if d > r1 + r2:
            # Circles too far apart - return point on line between them
            ratio = r1 / (r1 + r2)
            intersection_x = x1 + ratio * (x2 - x1)
            intersection_y = y1 + ratio * (y2 - y1)
            return [(intersection_x, intersection_y)]
        
        if d < abs(r1 - r2):
            # One circle inside the other
            if r1 < r2:
                return [(x1, y1)]
            else:
                return [(x2, y2)]
        
        # Normal intersection case
        try:
            a = (r1**2 - r2**2 + d**2) / (2 * d)
            h_squared = r1**2 - a**2
            
            if h_squared < 0:
                intersection_x = x1 + a * (x2 - x1) / d
                intersection_y = y1 + a * (y2 - y1) / d
                return [(intersection_x, intersection_y)]
            
            h = math.sqrt(h_squared)
            
            # Point on line between centers
            px = x1 + a * (x2 - x1) / d
            py = y1 + a * (y2 - y1) / d
            
            # Intersection points
            intersections = [
                (px + h * (y2 - y1) / d, py - h * (x2 - x1) / d),
                (px - h * (y2 - y1) / d, py + h * (x2 - x1) / d)
            ]
            
            return intersections
        except Exception:
            return [((x1 + x2) / 2, (y1 + y2) / 2)]
    
    def triangulate_device_position(self, measurements: List[DeviceRSSI]) -> Optional[TriangulationResult]:
        """Perform triangulation using multiple RSSI measurements"""
        if len(measurements) < 2:
            return None
        
        # Use first two measurements for initial triangulation
        pos1 = measurements[0].position
        pos2 = measurements[1].position
        r1 = measurements[0].distance_estimate
        r2 = measurements[1].distance_estimate
        
        intersections = self.calculate_circle_intersection(
            pos1.x, pos1.y, r1,
            pos2.x, pos2.y, r2
        )
        
        if not intersections:
            return None
        
        # If we have a third measurement, use it to refine the position
        if len(measurements) >= 3:
            pos3 = measurements[2].position
            r3 = measurements[2].distance_estimate
            
            # Find the intersection point closest to the third circle
            best_point = intersections[0]
            min_error = float('inf')
            
            for point in intersections:
                distance_to_third = math.sqrt((point[0] - pos3.x)**2 + (point[1] - pos3.y)**2)
                error = abs(distance_to_third - r3)
                if error < min_error:
                    min_error = error
                    best_point = point
            
            calculated_position = best_point
            confidence_score = max(0, 100 - min_error * 2)
        else:
            calculated_position = intersections[0]
            confidence_score = 70
        
        # Error analysis
        error_analysis = {}
        for i, measurement in enumerate(measurements):
            predicted_distance = math.sqrt(
                (calculated_position[0] - measurement.position.x)**2 + 
                (calculated_position[1] - measurement.position.y)**2
            )
            actual_distance = measurement.distance_estimate
            error = abs(predicted_distance - actual_distance)
            error_analysis[f"position_{i+1}_error_ft"] = round(error, 1)
        
        return TriangulationResult(
            mac_address="",  # Will be set by caller
            calculated_position=calculated_position,
            confidence_score=confidence_score,
            position_measurements=measurements,
            error_analysis=error_analysis
        )
    
    def calibrate_with_user_device(self, device_measurements: Dict[str, List[DeviceRSSI]]) -> Dict:
        """Calibrate triangulation using user's router as reference point"""
        calibration_info = {
            "user_router_detected": False,
            "calibration_applied": False,
            "router_positions": {},
            "calibration_offset": {"x": 0, "y": 0}
        }
        
        if not self.user_mac_address:
            return calibration_info
        
        # Look for user's router in measurements
        user_measurements = device_measurements.get(self.user_mac_address, [])
        
        if len(user_measurements) >= 2:
            calibration_info["user_router_detected"] = True
            
            # Record router signal strength at each position
            for measurement in user_measurements:
                position_name = measurement.position.name
                calibration_info["router_positions"][position_name] = {
                    "rssi": measurement.rssi,
                    "distance_estimate": measurement.distance_estimate,
                    "coordinates": f"({measurement.position.x}ft, {measurement.position.y}ft)"
                }
            
            # Find strongest signal position (closest to router)
            strongest_measurement = min(user_measurements, key=lambda m: abs(m.rssi))
            router_closest_position = strongest_measurement.position
            
            # If router is strongest at rssi1, that confirms our coordinate system
            if router_closest_position.name == "rssi1":
                calibration_info["calibration_applied"] = True
                calibration_info["router_location"] = "Confirmed at reference position (0,0)"
            else:
                calibration_info["calibration_applied"] = True
                calibration_info["router_location"] = f"Router closest to {router_closest_position.name} position"
        
        return calibration_info
    
    def generate_location_estimate(self, x: float, y: float, include_router_reference: bool = True) -> str:
        """Generate human-readable location estimate with router reference"""
        # Calculate distance from router (assumed at origin)
        distance_from_router = math.sqrt(x**2 + y**2)
        
        # Generate directional estimate
        if abs(x) <= 5 and abs(y) <= 5:
            base_location = "Very close to router position (same room)"
        elif x < -10:
            base_location = f"West of router ({abs(x):.1f}ft)"
        elif x > 40:
            base_location = f"Far east of router ({x:.1f}ft)"
        elif 15 <= x <= 25:
            base_location = "Near middle capture position"
        elif 30 <= x <= 40:
            base_location = "Near far capture position"
        elif x > 5:
            base_location = f"East of router ({x:.1f}ft)"
        else:
            base_location = f"Near router ({x:.1f}ft, {y:.1f}ft)"
        
        # Add router distance reference if enabled
        if include_router_reference and distance_from_router > 5:
            return f"{base_location} - {distance_from_router:.1f}ft from your router"
        else:
            return base_location
    
    def run_triangulation_analysis(self) -> Optional[Dict]:
        """Main triangulation analysis function that reads PCAP files directly"""
        print("🎯 CHECKING FOR TRIANGULATION OPPORTUNITY...")
        
        # Detect rssi PCAP files
        positions = self.detect_rssi_pcap_files()
        
        if len(positions) < 2:
            print(f"   ⚠️  Found {len(positions)} rssi PCAP files - need 2+ for triangulation")
            return None
        
        print(f"   ✅ Found {len(positions)} rssi PCAP files - running direct PCAP analysis")
        for pos in positions:
            print(f"      {pos.name}: ({pos.x}ft, {pos.y}ft) -> {os.path.basename(pos.pcap_file_path)}")
        
        # Check for user router
        if self.user_mac_address:
            print(f"   🏠 Looking for your router: {self.user_mac_address}")
        
        # Extract device measurements directly from PCAP files
        device_measurements = self.extract_device_measurements_from_pcaps(positions)
        
        if not device_measurements:
            print("   ⚠️  No device measurements found in PCAP files")
            return None
        
        print(f"   📊 Found {len(device_measurements)} devices across PCAP files")
        
        # Calibrate using user's router
        calibration_info = self.calibrate_with_user_device(device_measurements)
        
        if calibration_info["user_router_detected"]:
            print(f"   🎉 Your router detected! {calibration_info['router_location']}")
        
        # Perform triangulation
        triangulation_results = []
        multi_position_devices = []
        
        for mac_address, measurements in device_measurements.items():
            if len(measurements) >= 2:
                result = self.triangulate_device_position(measurements)
                if result:
                    result.mac_address = mac_address
                    triangulation_results.append(result)
                    
                    # Add to multi-position devices list
                    x, y = result.calculated_position
                    
                    # Enhanced location estimate with router reference
                    is_user_router = (mac_address == self.user_mac_address)
                    location_estimate = self.generate_location_estimate(x, y, include_router_reference=True)
                    
                    # Special handling for user's router
                    if is_user_router:
                        location_estimate = f"🏠 YOUR ROUTER - {location_estimate}"
                    
                    multi_position_device = {
                        "mac_address": mac_address,
                        "is_user_router": is_user_router,
                        "calculated_position": {
                            "x_ft": round(x, 1),
                            "y_ft": round(y, 1),
                            "coordinates": f"({x:.1f}ft, {y:.1f}ft)",
                            "distance_from_router_ft": round(math.sqrt(x**2 + y**2), 1)
                        },
                        "confidence_score": round(result.confidence_score, 1),
                        "location_estimate": location_estimate,
                        "measurements_used": len(result.position_measurements),
                        "position_measurements": [
                            {
                                "position": m.position.name,
                                "rssi_dbm": round(m.rssi, 1),
                                "distance_estimate_ft": m.distance_estimate,
                                "coordinates": f"({m.position.x}ft, {m.position.y}ft)"
                            }
                            for m in result.position_measurements
                        ],
                        "error_analysis": result.error_analysis
                    }
                    multi_position_devices.append(multi_position_device)
            else:
                print(f"   ⚠️  Device {mac_address}: Only {len(measurements)} measurement(s) - need 2+ for triangulation")
        
        if not triangulation_results:
            print("   ⚠️  No devices found in multiple positions")
            return None
        
        # Sort devices - user router first, then by distance from router
        multi_position_devices.sort(key=lambda d: (not d["is_user_router"], d["calculated_position"]["distance_from_router_ft"]))
        
        # Generate triangulation analysis summary
        triangulation_analysis = {
            "triangulation_summary": {
                "total_positions_analyzed": len(positions),
                "positions_used": [
                    {
                        "name": pos.name,
                        "coordinates": f"({pos.x}ft, {pos.y}ft)",
                        "pcap_file": os.path.basename(pos.pcap_file_path)
                    }
                    for pos in positions
                ],
                "total_devices_found": len(device_measurements),
                "multi_position_devices": len(triangulation_results),
                "triangulation_success_rate": f"{len(triangulation_results)}/{len(device_measurements)}",
                "user_router_detected": calibration_info["user_router_detected"],
                "data_source": "Direct PCAP analysis"
            },
            "router_calibration": calibration_info,
            "multi_position_devices": multi_position_devices,
            "spatial_intelligence": {
                "coordinate_system": "Router-referenced positioning (your router at approximate origin)",
                "measurement_unit": "feet",
                "confidence_scoring": "0-100% based on measurement consistency",
                "location_accuracy": "±10-20ft typical for indoor WiFi triangulation",
                "router_reference": f"Your router MAC: {self.user_mac_address}" if self.user_mac_address else "No router reference provided",
                "analysis_method": "Direct RSSI extraction from PCAP files"
            }
        }
        
        print(f"   ✅ Triangulation completed: {len(triangulation_results)} devices positioned")
        if calibration_info["user_router_detected"]:
            print(f"   🏠 Router calibration successful - enhanced spatial accuracy!")
        
        return triangulation_analysis

    def add_triangulation_analysis(self, consolidated_results: Dict, user_mac: str = "REPLACE_WITH_YOUR_ROUTER_MAC") -> Dict:  # <----ENTER YOUR ROUTER MAC ----
        """Add triangulation analysis by reading PCAP files directly"""
        try:
            print(f"🔍 TRIANGULATION DEBUG:")
            print(f"   PCAP Directory: {self.watch_directory}")
        
            # Initialize triangulation engine
            triangulation_engine = TriangulationEngine(
                pcap_directory=self.watch_directory,
                user_mac_address=user_mac,  # Your router MAC address
                packet_limit=None # <----- Change to analyze more packets, Starting with 3000 -----
            )
        
            # Run triangulation analysis on PCAP files
            triangulation_data = triangulation_engine.run_triangulation_analysis()
        
            if triangulation_data:
                consolidated_results["triangulation_analysis"] = triangulation_data
                print("✅ Triangulation analysis added to consolidated results")
            else:
                print("⚠️  Triangulation skipped - insufficient data")
            
        except Exception as e:
            print(f"⚠️  Triangulation analysis error: {e}")
            import traceback
            print(f"   Full traceback: {traceback.format_exc()}")
    
        return consolidated_results
    
    def analyze_threat_landscape(self, all_devices: Dict) -> Dict:
        """Analyze the overall threat landscape across all devices"""
        proximity_threats = []
        zone_distribution = {}
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
        for mac, device in all_devices.items():
            # Add MAC to device data for scoring
            device['mac_address'] = mac
            proximity_analysis = self.analyze_device_proximity(device)
        
            # Add device info
            proximity_analysis['mac_address'] = mac
            proximity_analysis['device_info'] = {
                'packet_count': device.get('packet_count', 0),
                'security_events': len(device.get('security_events', [])),
                'is_access_point': device.get('is_access_point', False),
                'is_user_router': mac.lower() == '<ROUTER_MAC_ADDRESS>'  # Your router MAC <---- Change to your router MAC ----
            }
        
            proximity_threats.append(proximity_analysis)
        
            # Update statistics - EXCLUDE YOUR ROUTER from threat counts
            zone = proximity_analysis['proximity_classification']['zone']
            risk_level = proximity_analysis['proximity_classification']['risk_level']
        
            if not proximity_analysis['device_info']['is_user_router']:
                zone_distribution[zone] = zone_distribution.get(zone, 0) + 1
                risk_summary[risk_level] += 1
    
        # Calculate immediate threats (exclude router)
        immediate_threats = sum(1 for threat in proximity_threats 
                          if threat['proximity_classification']['zone'] in ['immediate', 'close']
                          and not threat['device_info']['is_user_router'])
    
        close_proximity_devices = sum(1 for threat in proximity_threats
                                if threat['proximity_classification']['zone'] in ['immediate', 'close'] 
                                and not threat['device_info']['is_user_router'])
    
        return {
            'threat_landscape_summary': {
                'total_devices_analyzed': len(all_devices),
                'proximity_zone_distribution': zone_distribution,
                'risk_level_distribution': risk_summary,
                'immediate_threats': immediate_threats,
                'close_proximity_devices': close_proximity_devices,
                'user_router_detected': any(t['device_info']['is_user_router'] for t in proximity_threats)
            },
            'proximity_analysis_per_device': proximity_threats
        }


class WirelessForensicsAnalyzer:
    """Main analyzer orchestrator using Adapter pattern"""
    
    def __init__(self, watch_directory: str, output_directory: str, config: Dict = None):
        self.watch_directory = Path(watch_directory)
        self.output_directory = Path(output_directory)
        self.config = config or {}
        
        # Create output directory if it doesn't exist
        self.output_directory.mkdir(parents=True, exist_ok=True)

        # Store adapter reference for triangulation integration
        self._esp32_adapter = None
        
        # Initialize components
        self.adapter_factory = AdapterFactory()
        self.processor_queue = queue.Queue()
        self.results_queue = queue.Queue()
        
        # Threading
        self.processing_thread = None
        self.file_observer = None
        self.running = False
        
        # Results storage
        self.analysis_results = []
        self.consolidated_report = {
            'analysis_start': datetime.now().isoformat(),
            'wifi_results': [],
            'bluetooth_results': [],
            'correlation_results': [],
            'summary_statistics': {}
        }
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        logger.info(f"Starting monitoring of {self.watch_directory}")
        
        self.running = True
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._processing_worker, daemon=True)
        self.processing_thread.start()
        
        # Start file watcher
        event_handler = PcapFileHandler(self.processor_queue)
        self.file_observer = Observer()
        self.file_observer.schedule(event_handler, str(self.watch_directory), recursive=False)
        self.file_observer.start()
        
        logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        logger.info("Stopping monitoring...")
        
        self.running = False
        
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
        
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        logger.info("Monitoring stopped")
    
    def _processing_worker(self):
        """Background worker for processing files"""
        while self.running:
            try:
                # Get file from queue with timeout
                file_path = self.processor_queue.get(timeout=1)
                
                # Process the file
                self._process_single_file(file_path)
                
                # Update consolidated report
                self._update_consolidated_report()
                
                self.processor_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in processing worker: {e}")
    
    def _process_single_file(self, file_path: str):
        """Process a single PCAP file"""
        logger.info(f"Processing file: {file_path}")
        
        # Get appropriate adapter
        adapter = self.adapter_factory.get_adapter(file_path, self.config)
        
        if adapter:
            if hasattr(adapter, 'prepare_triangulation_data'):
                self._esp32_adapter = adapter

            result = adapter.parse_file(file_path)

            # Process the file
            self.analysis_results.append(result)
            
            # Save individual result
            self._save_individual_result(result, file_path)
            
            logger.info(f"Completed processing {file_path}: {result.statistics.get('processed_packets', 0)} packets")
        else:
            logger.warning(f"No adapter available for {file_path}")
    
    def _save_individual_result(self, result: AnalysisResult, file_path: str):
        """Save individual analysis result"""
        # timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # filename = f"{result.protocol.lower()}_{timestamp}_{Path(file_path).stem}.json"
        # output_path = self.output_directory / filename
        
        # Convert to serializable format
        # output_data = {
        #    'analysis_metadata': {
        #        'timestamp': datetime.now().isoformat(),
        #        'source_file': file_path,
        #        'protocol': result.protocol,
        #        'capture_source': result.capture_source,
        #        'adapter_used': result.metadata.get('adapter', 'Unknown')
        #    },
        #    'statistics': result.statistics,
        #    'devices': result.devices,
        #    'security_events': [asdict(event) for event in result.security_events],
        #    'metadata': result.metadata
        #}
        
        # Use compression for large files
        #if len(str(output_data)) > 1024 * 1024:  # > 1MB
        #    with gzip.open(f"{output_path}.gz", 'wt', encoding='utf-8') as f:
        #        json.dump(output_data, f, indent=2, default=str)
        #    logger.info(f"Saved compressed result: {output_path}.gz")
        #else:
        #    with open(output_path, 'w', encoding='utf-8') as f:
        #        json.dump(output_data, f, indent=2, default=str)
        #    logger.info(f"Saved result: {output_path}")
        #    logger.info(f"Processed {result.protocol} file: {Path(file_path).name}")

    def _update_consolidated_report(self):
        """Update the consolidated report with all results"""
        # Separate results by protocol
        wifi_results = [r for r in self.analysis_results if r.protocol == 'WiFi']
        bluetooth_results = [r for r in self.analysis_results if r.protocol == 'Bluetooth']
        
        # Update consolidated report
        self.consolidated_report.update({
            'last_updated': datetime.now().isoformat(),
            'wifi_results': [self._summarize_result(r) for r in wifi_results],
            'bluetooth_results': [self._summarize_result(r) for r in bluetooth_results],
            'summary_statistics': self._calculate_summary_statistics()
        })
        
        # Perform cross-protocol correlation
        if wifi_results and bluetooth_results:
            self.consolidated_report['correlation_results'] = self._correlate_protocols(wifi_results, bluetooth_results)
        
        # Save consolidated report
        self._save_consolidated_report()
    
    def _summarize_result(self, result: AnalysisResult) -> Dict:
        """Create summary of analysis result"""
        return {
            'protocol': result.protocol,
            'capture_source': result.capture_source,
            'device_count': len(result.devices),
            'security_event_count': len(result.security_events),
            'high_severity_events': len([e for e in result.security_events if e.severity == 'HIGH']),
            'processing_time': result.statistics.get('runtime_seconds', 0),
            'packet_count': result.statistics.get('processed_packets', 0),
            'file_path': result.metadata.get('file_path', 'Unknown')
        }
    
    def _calculate_summary_statistics(self) -> Dict:
        """Calculate overall summary statistics"""
        total_wifi_devices = sum(len(r.devices) for r in self.analysis_results if r.protocol == 'WiFi')
        total_bt_devices = sum(len(r.devices) for r in self.analysis_results if r.protocol == 'Bluetooth')
        total_security_events = sum(len(r.security_events) for r in self.analysis_results)
        high_severity_events = sum(
            len([e for e in r.security_events if e.severity == 'HIGH']) 
            for r in self.analysis_results
        )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(high_severity_events, total_security_events)
        
        triangulation_data = self.consolidated_report.get('triangulation_analysis', {})
        multi_position_devices = triangulation_data.get('multi_position_devices', [])
        triangulation_ready_count = len(multi_position_devices)

        return {
        'total_files_processed': len(self.analysis_results),
        'total_wifi_devices': total_wifi_devices,
        'total_bluetooth_devices': total_bt_devices,
        'total_security_events': total_security_events,
        'high_severity_events': high_severity_events,
        'risk_score': risk_score,
        'risk_level': self._get_risk_level(risk_score),
        # NEW: Triangulation readiness tracking
        'triangulation_readiness': {
            'wifi_devices_ready': triangulation_ready_count,
            'positions_analyzed': triangulation_data.get('triangulation_summary', {}).get('total_positions_analyzed', 0),
            'router_calibrated': triangulation_data.get('router_calibration', {}).get('user_router_detected', False)
        }
    }
    
    def _calculate_risk_score(self, high_severity: int, total_events: int) -> int:
        """Calculate overall risk score"""
        base_score = high_severity * 10 + total_events
        return min(base_score, 1000)  # Cap at 1000
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 500:
            return 'CRITICAL'
        elif score >= 200:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'
        
    def _correlate_wifi_bluetooth_devices(self, wifi_devices=None, bluetooth_devices=None):
        """Correlate WiFi and Bluetooth devices to identify potential device pairs"""
    
        # Safety check - continue if one type missing
        if not wifi_devices or not bluetooth_devices:
            return {"high_confidence_matches": [], "possible_matches": [], "note": "insufficient_data_for_correlation"}
    
        high_confidence = []
        possible_matches = []
    
        for wifi_mac, wifi_dev in wifi_devices.items():
            for bt_mac, bt_dev in bluetooth_devices.items():
                confidence, reasons = self._calculate_correlation_confidence(wifi_dev, bt_dev)
            
                if confidence >= 0.80:  # High confidence threshold
                    high_confidence.append({
                        "wifi_mac": wifi_mac, "bluetooth_mac": bt_mac, 
                        "confidence": round(confidence, 2), "reasons": reasons
                    })
                elif confidence >= 0.50:  # Possible match threshold
                    possible_matches.append({
                        "wifi_mac": wifi_mac, "bluetooth_mac": bt_mac,
                        "confidence": round(confidence, 2), "reasons": reasons
                    })
    
        return {
            "high_confidence_matches": high_confidence,
            "possible_matches": possible_matches,
            "analysis_summary": {
                "wifi_devices_analyzed": len(wifi_devices),
                "bluetooth_devices_analyzed": len(bluetooth_devices),
                "high_confidence_correlations": len(high_confidence),
                "possible_correlations": len(possible_matches)
            }
        }
    
    def _calculate_correlation_confidence(self, wifi_dev, bt_dev):
        """Calculate correlation confidence between WiFi and Bluetooth devices"""
        confidence = 0.0
        reasons = []
    
        # Manufacturer matching (strongest indicator)
        wifi_manufacturer = (wifi_dev.get('manufacturer') or '').lower()
        bt_manufacturer = (bt_dev.get('manufacturer') or '').lower()
    
        if wifi_manufacturer and bt_manufacturer and wifi_manufacturer == bt_manufacturer:
            confidence += 0.40
            reasons.append("manufacturer_match")
    
        # RSSI similarity analysis
        wifi_rssi = self._get_device_rssi_stats(wifi_dev)
        bt_rssi = self._get_device_rssi_stats(bt_dev)
    
        if wifi_rssi and bt_rssi:
            rssi_similarity = self._compare_rssi_patterns(wifi_rssi, bt_rssi)
            if rssi_similarity > 0.7:  # Similar signal patterns
                confidence += 0.25
                reasons.append("rssi_similarity")
            elif rssi_similarity > 0.5:
                confidence += 0.15
                reasons.append("rssi_weak_similarity")
    
        # Timing overlap analysis
        timing_overlap = self._analyze_timing_overlap(wifi_dev, bt_dev)
        if timing_overlap > 0.8:  # Strong timing correlation
            confidence += 0.20
            reasons.append("timing_overlap")
        elif timing_overlap > 0.5:
            confidence += 0.10
            reasons.append("timing_weak_overlap")
    
        # Apple ecosystem bonus (iPhone + AirPods pattern)
        if "apple" in wifi_manufacturer and "apple" in bt_manufacturer:
            confidence += 0.15
            reasons.append("apple_ecosystem")
    
        return min(confidence, 1.0), reasons
    
    def _get_device_rssi_stats(self, device):
        """Extract RSSI statistics from device data"""
        # Try compressed statistics first
        if 'rssi_statistics' in device and device['rssi_statistics'].get('count', 0) > 0:
            return device['rssi_statistics']
    
        # Fallback to raw readings
        rssi_readings = device.get('rssi_readings', [])
        if rssi_readings:
            return {
                'avg': sum(rssi_readings) / len(rssi_readings),
                'count': len(rssi_readings),
                'max': max(rssi_readings),
                'min': min(rssi_readings)
            }
        return None
    
    def _compare_rssi_patterns(self, wifi_rssi, bt_rssi):
        """Compare RSSI patterns for similarity (0.0 to 1.0)"""
        # Compare average RSSI values (within 10 dBm = similar location)
        avg_diff = abs(wifi_rssi['avg'] - bt_rssi['avg'])
        if avg_diff <= 10:
            similarity = 1.0 - (avg_diff / 10.0)  # Closer = higher similarity
        else:
            similarity = 0.0
    
        # Bonus for similar signal ranges (both stable or both variable)
        wifi_range = wifi_rssi.get('max', 0) - wifi_rssi.get('min', 0)
        bt_range = bt_rssi.get('max', 0) - bt_rssi.get('min', 0)
    
        if abs(wifi_range - bt_range) <= 5:  # Similar signal variability
            similarity += 0.2
    
        return min(similarity, 1.0)
    
    def _analyze_timing_overlap(self, wifi_dev, bt_dev):
        """Analyze timing overlap between devices (0.0 to 1.0)"""
        try:
            from datetime import datetime
        
            wifi_first = datetime.fromisoformat(wifi_dev.get('first_seen', '').replace('Z', '+00:00'))
            wifi_last = datetime.fromisoformat(wifi_dev.get('last_seen', '').replace('Z', '+00:00'))
            bt_first = datetime.fromisoformat(bt_dev.get('first_seen', '').replace('Z', '+00:00'))
            bt_last = datetime.fromisoformat(bt_dev.get('last_seen', '').replace('Z', '+00:00'))
        
            # Calculate overlap period
            overlap_start = max(wifi_first, bt_first)
            overlap_end = min(wifi_last, bt_last)
        
            if overlap_start >= overlap_end:
                return 0.0  # No overlap
        
            overlap_duration = (overlap_end - overlap_start).total_seconds()
            total_duration = max((wifi_last - wifi_first).total_seconds(), 
                               (bt_last - bt_first).total_seconds())
        
            return min(overlap_duration / max(total_duration, 1), 1.0)
    
        except:
            return 0.0  # Error in timestamp parsing
    
    def _correlate_protocols(self, wifi_results: List[AnalysisResult], 
                           bluetooth_results: List[AnalysisResult]) -> List[Dict]:
        """Correlate devices across WiFi and Bluetooth protocols"""
        correlations = []
        
        # Get all devices from both protocols
        wifi_devices = {}
        for result in wifi_results:
            wifi_devices.update(result.devices)
        
        bluetooth_devices = {}
        for result in bluetooth_results:
            bluetooth_devices.update(result.devices)
        
        # Perform correlations
        correlations.extend(self._oui_correlation(wifi_devices, bluetooth_devices))
        correlations.extend(self._temporal_correlation(wifi_devices, bluetooth_devices))
        correlations.extend(self._signal_correlation(wifi_devices, bluetooth_devices))
        
        return correlations
    
    def _oui_correlation(self, wifi_devices: Dict, bluetooth_devices: Dict) -> List[Dict]:
        """Correlate devices by manufacturer OUI"""
        correlations = []
        
        for wifi_addr, wifi_device in wifi_devices.items():
            wifi_oui = wifi_addr.replace(':', '').upper()[:6]
            
            for bt_addr, bt_device in bluetooth_devices.items():
                # Skip random addresses for OUI correlation
                if bt_device.get('is_random_address', False):
                    continue
                
                bt_oui = bt_addr.replace(':', '').upper()[:6]
                
                if wifi_oui == bt_oui:
                    correlations.append({
                        'type': 'manufacturer_match',
                        'wifi_device': wifi_addr,
                        'bluetooth_device': bt_addr,
                        'confidence': 'high',
                        'evidence': f'matching_oui_{wifi_oui}'
                    })
        
        return correlations
    
    def _temporal_correlation(self, wifi_devices: Dict, bluetooth_devices: Dict) -> List[Dict]:
        """Correlate devices by temporal activity"""
        correlations = []
        time_threshold = 30  # seconds
        
        for wifi_addr, wifi_device in wifi_devices.items():
            wifi_first = wifi_device.get('first_seen')
            wifi_last = wifi_device.get('last_seen')
            
            if not wifi_first or not wifi_last:
                continue
            
            for bt_addr, bt_device in bluetooth_devices.items():
                bt_first = bt_device.get('first_seen')
                bt_last = bt_device.get('last_seen')
                
                if not bt_first or not bt_last:
                    continue
                
                # Check for temporal overlap
                if self._check_time_overlap(wifi_first, wifi_last, bt_first, bt_last, time_threshold):
                    correlations.append({
                        'type': 'temporal_correlation',
                        'wifi_device': wifi_addr,
                        'bluetooth_device': bt_addr,
                        'confidence': 'medium',
                        'evidence': 'simultaneous_activity'
                    })
        
        return correlations
    
    def _signal_correlation(self, wifi_devices: Dict, bluetooth_devices: Dict) -> List[Dict]:
        """Correlate devices by signal strength (proximity)"""
        correlations = []
        
        for wifi_addr, wifi_device in wifi_devices.items():
            wifi_rssi = wifi_device.get('rssi_readings', [])
            if not wifi_rssi:
                continue
            wifi_avg = sum(wifi_rssi) / len(wifi_rssi)
            
            for bt_addr, bt_device in bluetooth_devices.items():
                bt_rssi = bt_device.get('rssi_readings', [])
                if not bt_rssi:
                    continue
                bt_avg = sum(bt_rssi) / len(bt_rssi)
                
                # Check if signals are similar (within 10 dBm)
                if abs(wifi_avg - bt_avg) <= 10:
                    correlations.append({
                        'type': 'signal_correlation',
                        'wifi_device': wifi_addr,
                        'bluetooth_device': bt_addr,
                        'confidence': 'low',
                        'evidence': f'similar_rssi_wifi_{wifi_avg:.1f}_bt_{bt_avg:.1f}'
                    })
        
        return correlations
    
    def _check_time_overlap(self, w_first: str, w_last: str, b_first: str, b_last: str, threshold: int) -> bool:
        """Check if time periods overlap within threshold"""
        try:
            # Parse timestamps
            w_first_dt = datetime.fromisoformat(w_first.replace('Z', '+00:00'))
            w_last_dt = datetime.fromisoformat(w_last.replace('Z', '+00:00'))
            b_first_dt = datetime.fromisoformat(b_first.replace('Z', '+00:00'))
            b_last_dt = datetime.fromisoformat(b_last.replace('Z', '+00:00'))
            
            # Check for overlap with threshold
            return not (w_last_dt < b_first_dt - timedelta(seconds=threshold) or 
                       b_last_dt < w_first_dt - timedelta(seconds=threshold))
        except:
            return False
    
    def _save_consolidated_report(self):
        """Save the consolidated report with detailed device data"""
    
        # Separate results by protocol
        wifi_results = [r for r in self.analysis_results if r.protocol == 'WiFi']
        bluetooth_results = [r for r in self.analysis_results if r.protocol == 'Bluetooth']
        network_results = [r for r in self.analysis_results if r.protocol == 'NetworkTraffic']
    
        # Compile detailed device data
        all_wifi_devices = {}
        all_bluetooth_devices = {}
        all_network_connections = {}
    
        for result in wifi_results:
            all_wifi_devices.update(result.devices)
    
        for result in bluetooth_results:
            all_bluetooth_devices.update(result.devices)
    
        for result in network_results:
            all_network_connections.update(result.devices)
    
        # Calculate comprehensive RSSI analysis
        rssi_analysis = self._calculate_comprehensive_rssi_analysis(all_wifi_devices)
    
        # Update consolidated report with FULL data
        self.consolidated_report.update({
            'last_updated': datetime.now().isoformat(),
            'wifi_results': [self._summarize_result(r) for r in wifi_results],
            'bluetooth_results': [self._summarize_result(r) for r in bluetooth_results],
            'network_results': [self._summarize_result(r) for r in network_results],
            'summary_statistics': self._calculate_summary_statistics(),
        
        # ADD DETAILED DATA HERE
        'detailed_analysis': {
            'wifi_devices': all_wifi_devices,
            'bluetooth_devices': all_bluetooth_devices,
            'network_connections': all_network_connections,
            'rssi_analysis': rssi_analysis,
            'device_intelligence': self._generate_device_intelligence(all_wifi_devices, all_bluetooth_devices)
        }
    })
    
        # Perform cross-protocol correlation
        if wifi_results and bluetooth_results:
            self.consolidated_report['correlation_results'] = self._correlate_protocols(wifi_results, bluetooth_results)
    
            # NEW: Enhanced device correlation
            correlation_analysis = self._correlate_wifi_bluetooth_devices(all_wifi_devices, all_bluetooth_devices)
            self.consolidated_report['device_correlation'] = correlation_analysis

        self.add_threat_landscape_analysis(all_wifi_devices)
        from wf_postreduce import apply_all
        apply_all(self.consolidated_report, calib_offsets={"2.4": 2.0, "5": 2.0, "6": 0.0})
        self.consolidated_report = self.add_triangulation_analysis(self.consolidated_report)
        self.consolidated_report = self.add_triangulation_analysis(self.consolidated_report)

        self.consolidated_report['summary_statistics'] = self._calculate_summary_statistics()
    
        # Update consolidated report with other data
        self.consolidated_report.update({
            'last_updated': datetime.now().isoformat(),
            'wifi_results': [self._summarize_result(r) for r in wifi_results],
            'bluetooth_results': [self._summarize_result(r) for r in bluetooth_results],
            'network_results': [self._summarize_result(r) for r in network_results],
            'detailed_analysis': {
                'wifi_devices': all_wifi_devices,
                'bluetooth_devices': all_bluetooth_devices,
                'network_connections': all_network_connections,
                'rssi_analysis': rssi_analysis,
                'device_intelligence': self._generate_device_intelligence(all_wifi_devices, all_bluetooth_devices)
            }
        })

        # Save consolidated report
        report_path = self.output_directory / "pcap_analysis.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.consolidated_report, f, indent=2, default=str)
    
        logger.info(f"Updated consolidated report: {report_path}")

    def add_threat_landscape_analysis(self, all_wifi_devices: Dict):
        """
        Add comprehensive threat landscape analysis to consolidated report
        """
        triangulation_engine = RSSTTriangulationEngine()
        threat_landscape = triangulation_engine.analyze_threat_landscape(all_wifi_devices)
    
        # Add to consolidated report
        self.consolidated_report['threat_landscape'] = threat_landscape
    
        # Update risk level based on proximity threats
        immediate_threats = threat_landscape['threat_landscape_summary']['immediate_threats']
        if immediate_threats > 0:
            self.consolidated_report['summary_statistics']['proximity_risk_level'] = 'HIGH'
            self.consolidated_report['summary_statistics']['immediate_proximity_threats'] = immediate_threats

    def _calculate_comprehensive_rssi_analysis(self, wifi_devices):
        """Calculate comprehensive RSSI analysis from all WiFi devices"""
        all_rssi = []
        device_rssi_stats = {}
    
        for bssid, device in wifi_devices.items():
            rssi_readings = device.get('rssi_readings', [])
            if rssi_readings:
                all_rssi.extend(rssi_readings)
                device_rssi_stats[bssid] = {
                    'ssid': device.get('ssid', 'Hidden'),
                    'min_rssi': min(rssi_readings),
                    'max_rssi': max(rssi_readings),
                    'avg_rssi': round(sum(rssi_readings) / len(rssi_readings), 2),
                    'measurement_count': len(rssi_readings),
                    'signal_quality': self._categorize_signal_strength(max(rssi_readings))
            }
    
        if not all_rssi:
            return {}
    
        return {
            'total_measurements': len(all_rssi),
            'overall_min_rssi': min(all_rssi),
            'overall_max_rssi': max(all_rssi),
            'overall_avg_rssi': round(sum(all_rssi) / len(all_rssi), 2),
            'signal_distribution': {
                'excellent_(-30_to_0)': len([r for r in all_rssi if r >= -30]),
                'very_good_(-50_to_-30)': len([r for r in all_rssi if -50 <= r < -30]),
                'good_(-60_to_-50)': len([r for r in all_rssi if -60 <= r < -50]),
                'fair_(-70_to_-60)': len([r for r in all_rssi if -70 <= r < -60]),
                'weak_(-80_to_-70)': len([r for r in all_rssi if -80 <= r < -70]),
                'very_weak_(<-80)': len([r for r in all_rssi if r < -80])
            },
        'strongest_signals': sorted([
            {'bssid': bssid, 'ssid': stats['ssid'], 'max_rssi': stats['max_rssi']}
            for bssid, stats in device_rssi_stats.items()
        ], key=lambda x: x['max_rssi'], reverse=True)[:10],
        'device_details': device_rssi_stats
    }

    def _categorize_signal_strength(self, rssi):
        """Categorize signal strength"""
        if rssi >= -30:
            return 'Excellent'
        elif rssi >= -50:
            return 'Very Good' 
        elif rssi >= -60:
            return 'Good'
        elif rssi >= -70:
            return 'Fair'
        elif rssi >= -80:
            return 'Weak'
        else:
            return 'Very Weak'

    def _generate_device_intelligence(self, wifi_devices, bluetooth_devices):
        """Generate device intelligence summary"""
        return {
            'wifi_summary': {
                'devices_with_rssi': len([d for d in wifi_devices.values() if d.get('rssi_readings')]),
                'hidden_networks': len([d for d in wifi_devices.values() if d.get('is_hidden')]),
                'open_networks': len([d for d in wifi_devices.values() if d.get('encryption') == 'Open'])
            },
            'bluetooth_summary': {
                'total_devices': len(bluetooth_devices),
                'random_addresses': len([d for d in bluetooth_devices.values() if d.get('is_random_address')]),
                'named_devices': len([d for d in bluetooth_devices.values() if d.get('name')])
            }
        }
    
    def process_existing_files(self):
        """Process any existing PCAP files in the watch directory"""
        logger.info("Processing existing PCAP files...")
        
        pcap_files = list(self.watch_directory.glob("*.pcap"))
        
        for file_path in pcap_files:
            logger.info(f"Processing existing file: {file_path}")
            self._process_single_file(str(file_path))
        
        if pcap_files:
            self._update_consolidated_report()
            logger.info(f"Processed {len(pcap_files)} existing files")
        else:
            logger.info("No existing PCAP files found")
    
    def generate_summary_report(self) -> Dict:
        """Generate a comprehensive summary report"""
        summary = {
            'report_generated': datetime.now().isoformat(),
            'analysis_period': {
                'start': self.consolidated_report.get('analysis_start'),
                'end': datetime.now().isoformat()
            },
            'overview': self.consolidated_report.get('summary_statistics', {}),
            'protocol_breakdown': {
                'wifi': {
                    'files_processed': len(self.consolidated_report.get('wifi_results', [])),
                    'total_devices': sum(r.get('device_count', 0) for r in self.consolidated_report.get('wifi_results', [])),
                    'security_events': sum(r.get('security_event_count', 0) for r in self.consolidated_report.get('wifi_results', []))
                },
                'bluetooth': {
                    'files_processed': len(self.consolidated_report.get('bluetooth_results', [])),
                    'total_devices': sum(r.get('device_count', 0) for r in self.consolidated_report.get('bluetooth_results', [])),
                    'security_events': sum(r.get('security_event_count', 0) for r in self.consolidated_report.get('bluetooth_results', []))
                }
            },
            'correlations': {
                'total_correlations': len(self.consolidated_report.get('correlation_results', [])),
                'high_confidence': len([c for c in self.consolidated_report.get('correlation_results', []) if c.get('confidence') == 'high']),
                'medium_confidence': len([c for c in self.consolidated_report.get('correlation_results', []) if c.get('confidence') == 'medium']),
                'low_confidence': len([c for c in self.consolidated_report.get('correlation_results', []) if c.get('confidence') == 'low'])
            },
            'recommendations': self._generate_recommendations()
        }
        
        return summary
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        stats = self.consolidated_report.get('summary_statistics', {})
        
        # Risk-based recommendations
        risk_level = stats.get('risk_level', 'LOW')
        if risk_level == 'CRITICAL':
            recommendations.append("IMMEDIATE ACTION REQUIRED: Critical security threats detected")
            recommendations.append("Review all HIGH severity security events immediately")
            recommendations.append("Consider implementing additional network monitoring")
        
        # High severity event recommendations
        high_events = stats.get('high_severity_events', 0)
        if high_events > 0:
            recommendations.append(f"Investigate {high_events} high-severity security events")
        
        # Protocol-specific recommendations
        wifi_results = self.consolidated_report.get('wifi_results', [])
        bt_results = self.consolidated_report.get('bluetooth_results', [])
        
        if wifi_results:
            recommendations.append("Monitor honeypot networks for suspicious activity")
            recommendations.append("Enable Protected Management Frames (PMF) on all access points")
        
        if bt_results:
            recommendations.append("Monitor Bluetooth device privacy practices")
            recommendations.append("Investigate devices with excessive activity patterns")
        
        # Correlation recommendations
        correlations = self.consolidated_report.get('correlation_results', [])
        if correlations:
            recommendations.append(f"Review {len(correlations)} cross-protocol device correlations")
        
        return recommendations
    
    def add_triangulation_analysis(self, consolidated_results: Dict, user_mac: str = "<ROUTER_MAC_ADDRESS>") -> Dict: # <----- REPLACE WITH ACTUAL MAC
        """Add triangulation analysis using both PCAP files AND processed device data"""
        try:
            print(f"🔍 TRIANGULATION DEBUG:")
            print(f"   PCAP Directory: {self.watch_directory}")
        
            # Initialize triangulation engine for PCAP analysis
            triangulation_engine = TriangulationEngine(
                pcap_directory=str(self.watch_directory),
                user_mac_address=user_mac,
                packet_limit=5000  # Configurable
            )
        
            # Run PCAP-based triangulation analysis
            triangulation_data = triangulation_engine.run_triangulation_analysis()
        
            # Also try device-based proximity analysis if we have processed devices
            wifi_devices = consolidated_results.get('detailed_analysis', {}).get('wifi_devices', {})
            if wifi_devices:
                print("   📊 Adding device-based proximity analysis...")
            
                # Get ESP32 adapter to prepare data (you'll need to store this reference)
                if hasattr(self, '_esp32_adapter'):
                    triangulation_ready_data = self._esp32_adapter.prepare_triangulation_data(wifi_devices)
                
                    # Use your existing RSSTTriangulationEngine for proximity analysis
                    from adapter_interfaces import RSSTTriangulationEngine  # Corrected import path
                    proximity_engine = RSSTTriangulationEngine()
                    proximity_analysis = proximity_engine.analyze_threat_landscape(triangulation_ready_data)
                
                    # Add proximity analysis to results
                    if triangulation_data:
                        triangulation_data['proximity_analysis'] = proximity_analysis
                    else:
                        triangulation_data = {'proximity_analysis_only': proximity_analysis}
        
            if triangulation_data:
                consolidated_results["triangulation_analysis"] = triangulation_data
                print("✅ Triangulation analysis added to results")
            else:
                print("⚠️  Triangulation skipped - insufficient data")
            
        except Exception as e:
            print(f"⚠️  Triangulation analysis error: {e}")
            import traceback
            print(f"   Full traceback: {traceback.format_exc()}")

        return consolidated_results
    
    # =============================================================================
    # CONFIGURATION AND MAIN EXECUTION
    # =============================================================================
    
    def create_default_config() -> Dict:
        """Create default configuration"""
        return {
            'honeypot_networks': [
            'Admin_Network_Test',
            'casa_IoT',
            'mis_invitadas'
            ],
            'security_thresholds': {
            'deauth_attack_threshold': 20,
            'deauth_time_window': 60,
            'high_activity_threshold': 1000,
            'evil_twin_sensitivity': 'medium'
            },
            'output_settings': {
            'compress_large_files': True,
            'compression_threshold_mb': 1,
            'save_individual_results': True,
            'update_consolidated_report': True
            },
            'processing_settings': {
            'max_packet_buffer': 10000,
            'progress_report_interval': 10000,
            'file_processing_delay': 2
            }
        }   

    @staticmethod
    def main():
        """Main entry point"""
        # Configuration
        watch_directory = r"C:\Users\Gavin\Desktop\WiFI_BT pcaps"  # Update this path
        output_directory = r"C:\Users\Gavin\Desktop\WiFi & BT Analysis"
        config = WirelessForensicsAnalyzer.create_default_config()
    
        # Create analyzer
        analyzer = WirelessForensicsAnalyzer(watch_directory, output_directory, config)
    
        try:
            # Process any existing files
            analyzer.process_existing_files()
        
            # Start real-time monitoring
            analyzer.start_monitoring()
        
            logger.info("Wireless Forensics Analyzer is running...")
            logger.info("Press Ctrl+C to stop")
        
            # Keep running until interrupted
            while True:
                time.sleep(1)
            
                # Optionally generate periodic summary reports
                if datetime.now().minute % 15 == 0:  # Every 15 minutes
                    summary = analyzer.generate_summary_report()
                    summary_path = Path(output_directory) / f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
                    with open(summary_path, 'w') as f:
                        json.dump(summary, f, indent=2, default=str)
    
        except KeyboardInterrupt:
            logger.info("Shutting down analyzer...")
            analyzer.stop_monitoring()
    
        except Exception as e:
            logger.error(f"Critical error: {e}")
            analyzer.stop_monitoring()
    
        finally:
            # Generate final summary
            final_summary = analyzer.generate_summary_report()
            final_path = Path(output_directory) / f"final_analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(final_path, 'w') as f:
                json.dump(final_summary, f, indent=2, default=str)
        
            logger.info(f"Final summary saved: {final_path}")
            logger.info("Analysis complete")