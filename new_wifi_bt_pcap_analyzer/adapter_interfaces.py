import os
import time
import logging
import pyshark
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import asdict
from collections import defaultdict
from abc import ABC, abstractmethod
from dataclasses import dataclass
import math
import statistics

# Configure logging
logger = logging.getLogger(__name__)

# Import your data models
from data_model import WiFiDeviceData, BluetoothDeviceData, SecurityEvent, AnalysisResult, NetworkConnectionData, NetworkFlowSummary

# =============================================================================
# TRIANGULATION CLASS
# =============================================================================

@dataclass
class CapturePosition:
    """Represents a capture position with coordinates"""
    name: str
    x: float  # feet from reference point
    y: float  # feet from reference point
    description: str

class RSSTTriangulationEngine:
    """
    RSSI-based triangulation and proximity analysis engine
    """
    
    def __init__(self):
        # House layout configuration (adjust to your actual layout)
        self.capture_positions = {
            'position_1': CapturePosition('Living Room', 0, 0, 'Reference position'),
            'position_2': CapturePosition('Kitchen', 15, 0, '15ft east of living room'),
            'position_3': CapturePosition('Bedroom', 7, 12, '12ft north, 7ft east')
        }
        
        # RSSI to distance conversion parameters
        self.rssi_params = {
            'tx_power': -30,      # Transmitter power at 1 meter (dBm)
            'path_loss_exp': 2.0, # Path loss exponent (2.0 = free space)
            'environmental_factor': 3.0  # Indoor environment adjustment
        }
        
        # Threat proximity zones (feet)
        self.proximity_zones = {
            'immediate': 5,     # Same room
            'close': 15,        # Adjacent room  
            'neighbor_close': 25, # Close neighbor
            'neighbor_far': 40,   # Far neighbor
            'distant': 100       # Street/beyond
        }
    
    def rssi_to_distance(self, rssi: float) -> float:
        # Band-aware distance calculation
        band = "2.4"  # Default, you can enhance this
        ref_1m = -40.0 if band == "2.4" else -45.0
        n = 3.0
        distance_m = 10 ** ((ref_1m - rssi) / (10.0 * n))
        return max(3.0, distance_m * 3.28084)
    
    def analyze_device_proximity(self, device_data: Dict) -> Dict:
        """
        Analyze proximity for a single device across multiple capture positions
        """
        rssi_stats = device_data.get('rssi_statistics', {})
        
        if not rssi_stats or rssi_stats.get('count', 0) == 0:
            return self._create_empty_proximity_analysis()
        
        # Extract RSSI data
        avg_rssi = rssi_stats.get('avg', -100)
        max_rssi = rssi_stats.get('max', -100)
        min_rssi = rssi_stats.get('min', -100)
        
        # Calculate distance estimates
        avg_distance = self.rssi_to_distance(avg_rssi)
        closest_distance = self.rssi_to_distance(max_rssi)  # Strongest signal = closest
        farthest_distance = self.rssi_to_distance(min_rssi)
        
        # Determine proximity zone
        proximity_zone = self._classify_proximity_zone(closest_distance)
        
        # Calculate threat proximity score
        threat_score = self._calculate_threat_proximity_score(
            closest_distance, avg_distance, device_data
        )
        
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
        for zone, max_distance in self.proximity_zones.items():
            if distance <= max_distance:
                return zone
        return 'distant'
    
    def _calculate_threat_proximity_score(self, closest_dist: float, avg_dist: float, device_data: Dict) -> int:
        """
        Calculate threat proximity score (0-100)
        Higher score = more dangerous proximity
        """
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
            event_multiplier = min(len(security_events) / 10, 3.0)  # Cap at 3x
            base_score += 20 * event_multiplier
        
        # Signal strength consistency (stable signal = higher threat)
        rssi_stats = device_data.get('rssi_statistics', {})
        std_dev = rssi_stats.get('std_dev', 10)
        if std_dev < 5:  # Very consistent signal
            base_score += 10
        
        # Device activity level
        packet_count = device_data.get('packet_count', 0)
        if packet_count > 1000:  # High activity
            base_score += 10
        
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
    
    def analyze_threat_landscape(self, all_devices: Dict) -> Dict:
        """
        Analyze the overall threat landscape across all devices
        """
        proximity_threats = []
        zone_distribution = {}
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for mac, device in all_devices.items():
            proximity_analysis = self.analyze_device_proximity(device)
            
            # Add MAC address for reference
            proximity_analysis['mac_address'] = mac
            proximity_analysis['device_info'] = {
                'packet_count': device.get('packet_count', 0),
                'security_events': len(device.get('security_events', [])),
                'is_access_point': device.get('is_access_point', False)
            }
            
            proximity_threats.append(proximity_analysis)
            
            # Update statistics
            zone = proximity_analysis['proximity_classification']['zone']
            zone_distribution[zone] = zone_distribution.get(zone, 0) + 1
            
            risk_level = proximity_analysis['proximity_classification']['risk_level']
            risk_summary[risk_level] += 1
        
        # Sort by threat proximity score
        proximity_threats.sort(
            key=lambda x: x['proximity_classification']['threat_proximity_score'], 
            reverse=True
        )
        
        return {
            'threat_landscape_summary': {
                'total_devices_analyzed': len(all_devices),
                'proximity_zone_distribution': zone_distribution,
                'risk_level_distribution': risk_summary,
                'immediate_threats': risk_summary['CRITICAL'] + risk_summary['HIGH'],
                'close_proximity_devices': zone_distribution.get('immediate', 0) + zone_distribution.get('close', 0)
            },
            'high_priority_threats': [
                threat for threat in proximity_threats 
                if threat['proximity_classification']['threat_proximity_score'] >= 50
            ],
            'proximity_analysis_per_device': proximity_threats,
            'threat_intelligence': self._generate_threat_intelligence(proximity_threats)
        }
    
    def _generate_threat_intelligence(self, proximity_threats: List[Dict]) -> Dict:
        """Generate actionable threat intelligence"""
        intelligence = {
            'immediate_action_required': [],
            'monitoring_recommended': [],
            'insights': []
        }
        
        for threat in proximity_threats:
            mac = threat['mac_address']
            classification = threat['proximity_classification']
            device_info = threat['device_info']
            
            # Immediate action required
            if (classification['risk_level'] in ['CRITICAL', 'HIGH'] and 
                device_info['security_events'] > 0):
                intelligence['immediate_action_required'].append({
                    'device': mac,
                    'threat_level': classification['risk_level'],
                    'location': classification['location_estimate'],
                    'security_events': device_info['security_events'],
                    'recommendation': self._get_threat_recommendation(classification, device_info)
                })
            
            # Monitoring recommended
            elif classification['threat_proximity_score'] >= 30:
                intelligence['monitoring_recommended'].append({
                    'device': mac,
                    'location': classification['location_estimate'],
                    'reason': 'Close proximity with moderate activity'
                })
        
        # Generate insights
        intelligence['insights'] = self._generate_insights(proximity_threats)
        
        return intelligence
    
    def _get_threat_recommendation(self, classification: Dict, device_info: Dict) -> str:
        """Get specific threat recommendation"""
        if device_info['security_events'] > 10:
            return 'URGENT: Active attack detected - investigate immediately'
        elif classification['zone'] == 'immediate':
            return 'HIGH PRIORITY: Threat in immediate vicinity - verify legitimate device'
        elif classification['zone'] == 'close':
            return 'INVESTIGATE: Close proximity threat - monitor network activity'
        else:
            return 'MONITOR: Elevated threat level - continue surveillance'
    
    def _generate_insights(self, proximity_threats: List[Dict]) -> List[str]:
        """Generate analytical insights"""
        insights = []
        
        # Count threats by zone
        immediate_count = sum(1 for t in proximity_threats if t['proximity_classification']['zone'] == 'immediate')
        neighbor_count = sum(1 for t in proximity_threats if 'neighbor' in t['proximity_classification']['zone'])
        
        if immediate_count > 0:
            insights.append(f'{immediate_count} device(s) detected in immediate vicinity - verify all are authorized')
        
        if neighbor_count > 3:
            insights.append(f'{neighbor_count} devices from neighbor properties - normal residential density')
        
        # Security event patterns
        total_events = sum(t['device_info']['security_events'] for t in proximity_threats)
        if total_events > 0:
            insights.append(f'Total security events: {total_events} - investigate attack patterns')
        
        return insights

# =============================================================================
# ADAPTER INTERFACES
# =============================================================================

class CaptureAdapter(ABC):
    """Abstract base class for all capture adapters"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.processed_packets = 0
        self.start_time = time.time()
        self.devices = {}
        self.security_events = []
    
    @abstractmethod
    def can_handle(self, file_path: str) -> bool:
        """Check if this adapter can handle the given file"""
        pass
    
    @abstractmethod
    def parse_file(self, file_path: str) -> AnalysisResult:
        """Parse the capture file and return analysis results"""
        pass
    
    @abstractmethod
    def get_device_type(self) -> type:
        """Return the device data type this adapter handles"""
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        runtime = time.time() - self.start_time
        return {
            'processed_packets': self.processed_packets,
            'runtime_seconds': round(runtime, 2),
            'packets_per_second': round(self.processed_packets / runtime if runtime > 0 else 0, 2),
            'total_devices': len(self.devices),
            'security_events': len(self.security_events)
        }
    
    def reset_statistics(self):
        """Reset processing statistics"""
        self.processed_packets = 0
        self.start_time = time.time()
        self.devices.clear()
        self.security_events.clear()

class ESP32WiFiAdapter(CaptureAdapter):
    """Adapter for ESP32 WiFi captures"""

    def _process_management_frame_enhanced(self, packet, device, frame_subtype, bssid):
        """Process management frames with enhanced data extraction"""
    
        if frame_subtype == 8:  # Beacon frame
            self._process_beacon_frame(packet, device, bssid)
        elif frame_subtype == 4:  # Probe Request
            self._process_probe_request(packet, device)
        elif frame_subtype == 5:  # Probe Response
            self._process_probe_response(packet, device, bssid)
        elif frame_subtype in [0, 2, 10]:  # Association frames
            self._process_association_frame(packet, device, frame_subtype)
        elif frame_subtype == 12:  # Deauthentication
            self._process_deauth_frame(packet, device)
        elif frame_subtype == 10:  # Disassociation
            self._process_disassoc_frame(packet, device)

    def _process_beacon_frame(self, packet, device, bssid):
        """Extract comprehensive beacon frame data"""
        try:
            # Mark as access point
            device['is_access_point'] = True
            device['bssid'] = bssid
        
            # Extract SSID
            ssid = self._extract_ssid(packet)
            if ssid:
                device['ssid'] = ssid
                device['is_hidden'] = False
            else:
                device['is_hidden'] = True
        
            # Extract security information
            security_info = self._extract_security_info(packet)
            security_info = self._extract_security_info(packet)  # Ensure security_info is defined
            security_info = self._extract_security_info(packet)  # Ensure security_info is defined
            device.update(security_info)

            # Extract channel information
            channel_info = self._extract_channel_info(packet)
            device.update(channel_info)
        
            # Extract AP capabilities
            capabilities = self._extract_ap_capabilities(packet)
            device.update(capabilities)
        
            # Extract beacon interval
            if hasattr(packet.wlan_mgt, 'beacon_int'):
                device['beacon_interval'] = int(packet.wlan_mgt.beacon_int)
        
        except Exception as e:
            pass

    def _process_probe_request(self, packet, device):
        """Extract probe request intelligence"""
        try:
            # Extract requested SSIDs
            requested_ssids = self._extract_probe_ssids(packet)
            if requested_ssids:
                if 'probe_requests' not in device:
                    device['probe_requests'] = []
                device['probe_requests'].extend(requested_ssids)
            
            # Extract device capabilities from probe
            device_caps = self._extract_device_capabilities_from_probe(packet)
            if device_caps:
                device['device_capabilities'] = device_caps
            
            # Check for suspicious probing
            if self._is_suspicious_probe(requested_ssids):
                self._add_security_event(device, 'suspicious_probe', 
                                       f'Probing for suspicious SSIDs: {requested_ssids}')
        except Exception as e:
            pass

    def _extract_security_info(self, packet):
        """Extract comprehensive security information"""
        security_info = {
            'encryption': 'Unknown',
            'wpa_version': None,
            'cipher_suite': None,
            'akm_suite': None,
            'pmf_capable': False,
            'pmf_required': False
        }
    
        try:
            # Check for WPA/WPA2/WPA3 information
            if hasattr(packet, 'wlan_mgt'):
                # RSN (WPA2/WPA3) Information
                if hasattr(packet.wlan_mgt, 'rsn_version'):
                    security_info['wpa_version'] = 'WPA2/WPA3'
                    security_info['encryption'] = 'WPA2/WPA3'
                
                    # Extract cipher suites
                    if hasattr(packet.wlan_mgt, 'rsn_pcs_type'):
                        cipher_type = packet.wlan_mgt.rsn_pcs_type
                        if cipher_type == '4':
                            security_info['cipher_suite'] = 'CCMP-128'
                        elif cipher_type == '2':
                            security_info['cipher_suite'] = 'TKIP'
                
                    # Check PMF capability
                    if hasattr(packet.wlan_mgt, 'rsn_pmf_cap'):
                        security_info['pmf_capable'] = packet.wlan_mgt.rsn_pmf_cap == '1'
                    if hasattr(packet.wlan_mgt, 'rsn_pmf_req'):
                        security_info['pmf_required'] = packet.wlan_mgt.rsn_pmf_req == '1'
            
                # WPA Information
                elif hasattr(packet.wlan_mgt, 'wpa_version'):
                    security_info['wpa_version'] = 'WPA'
                    security_info['encryption'] = 'WPA'
            
                # Open network detection
                elif hasattr(packet.wlan_mgt, 'fixed_capabilities_privacy'):
                    if packet.wlan_mgt.fixed_capabilities_privacy == '0':
                        security_info['encryption'] = 'Open'
                    else:
                        security_info['encryption'] = 'WEP'
                    
        except Exception as e:
            pass
    
        return security_info

    def _process_probe_response(self, packet, device, bssid):
        """Process probe response frames"""
        try:
            device['bssid'] = bssid
        
            # Extract SSID from probe response
            ssid = self._extract_ssid(packet)
            if ssid:
                device['ssid'] = ssid
            
            # Extract security info
            security_info = self._extract_security_info(packet)
            device.update(security_info)
        
        except Exception as e:
            pass

    def _extract_channel_info(self, packet):
        """Extract channel and frequency information"""
        channel_info = {}
    
        try:
            # From radiotap header
            if hasattr(packet, 'radiotap'):
                if hasattr(packet.radiotap, 'channel_freq'):
                    freq = int(packet.radiotap.channel_freq)
                    channel_info['frequency_mhz'] = freq
                    channel_info['channel'] = self._freq_to_channel(freq)
                    channel_info['band'] = self._freq_to_band(freq)
        
            # From management frame
            if hasattr(packet, 'wlan_mgt'):
                if hasattr(packet.wlan_mgt, 'ds_current_channel'):
                    channel_info['channel'] = int(packet.wlan_mgt.ds_current_channel)
            
                # Country information
                if hasattr(packet.wlan_mgt, 'country_info_code'):
                    channel_info['country_code'] = packet.wlan_mgt.country_info_code
                
        except Exception as e:
            pass
    
        return channel_info

    def _extract_ap_capabilities(self, packet):
        """Extract access point capabilities"""
        capabilities = {}
    
        try:
            if hasattr(packet, 'wlan_mgt'):
                # 802.11n capabilities
                if hasattr(packet.wlan_mgt, 'ht_capabilities'):
                    capabilities['supports_80211n'] = True
                    if hasattr(packet.wlan_mgt, 'ht_cap_max_rx_ampdu_factor'):
                        capabilities['max_ampdu_length'] = packet.wlan_mgt.ht_cap_max_rx_ampdu_factor
            
                # 802.11ac capabilities
                if hasattr(packet.wlan_mgt, 'vht_capabilities'):
                    capabilities['supports_80211ac'] = True
                    if hasattr(packet.wlan_mgt, 'vht_cap_max_mpdu_length'):
                        capabilities['max_mpdu_length'] = packet.wlan_mgt.vht_cap_max_mpdu_length
            
                # 802.11ax capabilities
                if hasattr(packet.wlan_mgt, 'he_capabilities'):
                    capabilities['supports_80211ax'] = True
            
                # Short/Long preamble
                if hasattr(packet.wlan_mgt, 'fixed_capabilities_short_preamble'):
                    capabilities['short_preamble'] = packet.wlan_mgt.fixed_capabilities_short_preamble == '1'
                
        except Exception as e:
            pass
    
        return capabilities
    
    def _extract_probe_ssids(self, packet):
        """Extract SSIDs from probe requests"""
        ssids = []
        try:
            if hasattr(packet, 'wlan_mgt'):
            # Look for SSID information elements
                if hasattr(packet.wlan_mgt, 'ssid'):
                    ssid = packet.wlan_mgt.ssid
                    if ssid and ssid != '':
                        ssids.append(ssid)
        except Exception as e:
            pass
    
        return ssids

    def _extract_device_capabilities_from_probe(self, packet):
        """Extract device capabilities from probe requests"""
        capabilities = {}
    
        try:
            if hasattr(packet, 'wlan_mgt'):
                # Supported rates indicate device type
                if hasattr(packet.wlan_mgt, 'supported_rates'):
                    capabilities['supported_rates'] = packet.wlan_mgt.supported_rates
            
                # Extended capabilities
                if hasattr(packet.wlan_mgt, 'extcap'):
                    capabilities['extended_capabilities'] = packet.wlan_mgt.extcap
                
                # Power save capability
                if hasattr(packet.wlan_mgt, 'fixed_capabilities_ess'):
                    capabilities['power_save_capable'] = True
                
        except Exception as e:
            pass
    
        return capabilities

    def _is_suspicious_probe(self, ssids):
        """Detect suspicious probe request patterns"""
        suspicious_patterns = [
            'linksys', 'dlink', 'netgear', 'default', 'admin', 'test',
            'honeypot', 'monitor', 'corporate', 'guest'
        ]
    
        if not ssids:
            return False
    
        for ssid in ssids:
            ssid_lower = ssid.lower()
            for pattern in suspicious_patterns:
                if pattern in ssid_lower:
                    return True
    
        return False

    def _process_data_frame_enhanced(self, packet, device, frame_subtype):
        """Process data frames with enhanced analysis"""
        try:
            # QoS analysis
            if frame_subtype in [8, 9, 10, 11]:  # QoS data frames
                device['supports_qos'] = True
            
                # Extract QoS priority
                if hasattr(packet, 'wlan_qos'):
                    if hasattr(packet.wlan_qos, 'priority'):
                        priority = int(packet.wlan_qos.priority)
                        if 'qos_priorities' not in device:
                            device['qos_priorities'] = []
                        device['qos_priorities'].append(priority)
        
            # Power management analysis
            if hasattr(packet.wlan, 'fc_pwrmgt'):
                device['power_save_mode'] = packet.wlan.fc_pwrmgt == '1'
        
            # Retry analysis (network congestion indicator)
            if hasattr(packet.wlan, 'fc_retry'):
                if packet.wlan.fc_retry == '1':
                    device['retry_count'] = device.get('retry_count', 0) + 1
                
        except Exception as e:
            pass

    def _freq_to_channel(self, freq_mhz):
        """Convert frequency to channel number"""
        if 2412 <= freq_mhz <= 2484:
            if freq_mhz == 2484:
                return 14
            else:
                return (freq_mhz - 2412) // 5 + 1
        elif 5000 <= freq_mhz <= 6000:
            return (freq_mhz - 5000) // 5
        return None

    def _freq_to_band(self, freq_mhz):
        """Determine frequency band"""
        if 2400 <= freq_mhz <= 2500:
            return '2.4GHz'
        elif 5000 <= freq_mhz <= 6000:
            return '5GHz'
        elif 6000 <= freq_mhz <= 7000:
            return '6GHz'
        return 'Unknown'

    def _update_device_capabilities(self, packet, device):
        """Update device capabilities based on frame analysis"""
        try:
            # Frame retry behavior indicates network quality
            if hasattr(packet.wlan, 'fc_retry') and packet.wlan.fc_retry == '1':
                device['network_quality'] = 'poor'
        
            # Power management indicates mobile device
            if hasattr(packet.wlan, 'fc_pwrmgt') and packet.wlan.fc_pwrmgt == '1':
                device['device_type_hint'] = 'mobile'
        
            # Update frame type statistics
            if 'frame_types' not in device:
                device['frame_types'] = {'management': 0, 'control': 0, 'data': 0}
        
            fc_value = int(packet.wlan.fc.raw_value, 16) if isinstance(packet.wlan.fc.raw_value, str) else int(packet.wlan.fc.raw_value)
            frame_type = (fc_value >> 2) & 0x3
        
            if frame_type == 0:
                device['frame_types']['management'] += 1
            elif frame_type == 1:
                device['frame_types']['control'] += 1
            elif frame_type == 2:
                device['frame_types']['data'] += 1
            
        except Exception as e:
            pass

    def _create_device_entry(self, mac_address, packet):
        """Create enhanced device entry with comprehensive fields"""
        return {
            'mac_address': mac_address,
            'packet_count': 0,
            'rssi_readings': [],
            'first_seen': self._get_packet_timestamp(packet),
            'last_seen': self._get_packet_timestamp(packet),
            'security_events': [],
        
            # Network information
            'ssid': None,
            'bssid': None,
            'is_access_point': False,
            'is_hidden': False,
        
            # Security information
            'encryption': 'Unknown',
            'wpa_version': None,
            'cipher_suite': None,
            'pmf_capable': False,
            'pmf_required': False,
        
            # Technical capabilities
            'channel': None,
            'frequency_mhz': None,
            'band': None,
            'beacon_interval': None,
            'supports_80211n': False,
            'supports_80211ac': False,
            'supports_80211ax': False,
            'supports_qos': False,
        
            # Device behavior
            'probe_requests': [],
            'device_capabilities': {},
            'power_save_mode': False,
            'retry_count': 0,
            'frame_types': {'management': 0, 'control': 0, 'data': 0},
        
            # Intelligence
            'device_type_hint': 'unknown',
            'network_quality': 'good',
            'country_code': None
        }

    def prepare_triangulation_data(self, devices_dict) -> Dict:
        """Convert ESP32 device data to triangulation engine format"""
        triangulation_devices = {}
    
        for mac, device in devices_dict.items():
            # Extract RSSI statistics from your device data
            rssi_readings = device.get('rssi_readings', [])
        
            if rssi_readings:
                triangulation_devices[mac] = {
                    'rssi_statistics': {
                        'avg': sum(rssi_readings) / len(rssi_readings),
                        'max': max(rssi_readings),
                        'min': min(rssi_readings),
                        'count': len(rssi_readings),
                        'std_dev': self._calculate_std_dev(rssi_readings)
                    },
                    'packet_count': device.get('packet_count', 0),
                    'security_events': device.get('security_events', []),
                    'is_access_point': device.get('is_access_point', False)
                }
    
        return triangulation_devices

    def add_proximity_analysis_to_device_data(self, devices: Dict) -> Dict:
        """
        Add proximity analysis to device data during compression
        """
        triangulation_engine = RSSTTriangulationEngine()
    
        for mac, device in devices.items():
            # Add proximity analysis to each device
            proximity_analysis = triangulation_engine.analyze_device_proximity(device)
            device['proximity_analysis'] = proximity_analysis
    
        return devices
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.deauth_tracking = defaultdict(list)
        self.honeypot_networks = self.config.get('honeypot_networks', [
            'Admin_Network_Test', 'casa_IoT', 'mis_invitadas'
        ])
    
    def can_handle(self, file_path: str) -> bool:
        """Check if file is an ESP32 WiFi capture"""
        filename = Path(file_path).name.lower()
        wifi_patterns = ['raw_', 'esp32', 'wifi', 'rssi']
        return any(pattern in filename for pattern in wifi_patterns)
    
    def get_device_type(self) -> type:
        """Return WiFi device data type"""
        return WiFiDeviceData
    
    def debug_before_return(self):
        """Call this just before returning AnalysisResult"""
        print(f"\n🎯 DEBUG: FINAL STATUS before returning result")
        print(f"   Device count in self.devices: {len(getattr(self, 'devices', {}))}")
        print(f"   Security events count: {len(getattr(self, 'security_events', []))}")
    
        if hasattr(self, 'devices') and self.devices:
            print(f"   ✅ Devices exist - showing first 3:")
            for i, (mac, device) in enumerate(list(self.devices.items())[:3]):
                print(f"     {i+1}. {mac}: {device.get('packet_count', 0)} packets")
        else:
            print(f"   ❌ CRITICAL: self.devices is empty or doesn't exist!")

        # Check aggregated stats
        if hasattr(self, 'aggregated_security_stats'):
            stats = self.aggregated_security_stats
            print(f"   Security aggregation: {stats.get('total_events', 0)} events")
        else:
            print(f"   ⚠️  No aggregated security stats found")
    
    def parse_file(self, file_path: str) -> AnalysisResult:
        """Parse ESP32 WiFi PCAP file"""
        logger.info(f"ESP32 Adapter: Parsing {file_path}")
        # self.reset_statistics()
        
        # DEBUG MODE: Process limited packets to prevent crashes
        DEBUG_MODE = False  # Set to False for full processing
        MAX_PACKETS = None  # <---change to parse more packets: Set to None to analyze all for raw_.pcap and rssi.pcap


        try:
            # Configure PyShark for WiFi
            capture = pyshark.FileCapture(
                file_path,
                display_filter='wlan',
                include_raw=True,
                use_json=True
            )
            
            for packet in capture:
                self._process_packet(packet)
                self.processed_packets += 1
                
                if DEBUG_MODE and self.processed_packets >= MAX_PACKETS:
                    print(f"🐛 DEBUG: Stopping at {MAX_PACKETS} packets for testing")
                    break

                if self.processed_packets % 10000 == 0:
                    logger.info(f"ESP32: Processed {self.processed_packets} packets")
            
            capture.close()
            # self._post_process_analysis()
            self.compress_and_optimize_data()
            # ADD THIS LINE:
            self.debug_before_return()
            
            return self.create_analysis_result_with_fixes(file_path)
            
        except Exception as e:
            logger.error(f"ESP32 Adapter error: {e}")
            print(f"🚨 CRITICAL: Exception occurred, but preserving device data!")
            print(f"   Devices found: {len(getattr(self, 'devices', {}))}")
            print(f"   Exception: {e}")
    
            # PRESERVE THE DATA instead of returning empty result
            self.debug_before_return()
            return self.create_analysis_result_with_fixes(file_path)
    
    """
    Debug Version of _process_packet Method
    Tracks exactly where devices are being lost in the processing pipeline
    """

    def _process_control_frame(self, packet, device, frame_subtype):
        """Process control frames"""
        try:
            if 'frame_types' not in device:
                device['frame_types'] = set()
            device['frame_types'].add(f'control_{frame_subtype}')
        except Exception as e:
            pass

    def _process_packet(self, packet):
        """Enhanced packet processing with comprehensive data extraction"""

        # DEBUG MODE TOGGLE
        DEBUG_MODE = False  # Set to False to turn off all debug output
    
        # Debug counters
        if DEBUG_MODE:
            if self.processed_packets == 1:
                print(f"🔍 PACKET DEBUG: Processing first packet")
            if self.processed_packets % 50000 == 0:
                print(f"🔍 PACKET DEBUG: {self.processed_packets} packets, {len(getattr(self, 'devices', {}))} devices so far")
    
        try:
            # DEBUG: Check if packet has wlan layer
            if not hasattr(packet, 'wlan'):
                if DEBUG_MODE and self.processed_packets <= 5:  # Only show first few
                    print(f"🔍 DEBUG: Packet {self.processed_packets} has no wlan layer")
                return

            if DEBUG_MODE and self.processed_packets <= 5:
                print(f"🔍 DEBUG: Packet {self.processed_packets} - Has wlan layer")

            # Existing frame control parsing
            fc_raw = packet.wlan.fc.raw_value
            if isinstance(fc_raw, str) and fc_raw.startswith('0x'):
                fc_value = int(fc_raw, 16)
            else:
                fc_value = int(fc_raw)
    
            frame_type = (fc_value >> 2) & 0x3
            frame_subtype = (fc_value >> 4) & 0xF
    
            if DEBUG_MODE and self.processed_packets <= 5:
                print(f"🔍 DEBUG: Packet {self.processed_packets} - Frame parsed: type={frame_type}, subtype={frame_subtype}")


            # Extract basic info
            src_addr = getattr(packet.wlan, 'sa', None)
            dst_addr = getattr(packet.wlan, 'da', None)
            bssid = getattr(packet.wlan, 'bssid', None)
    
            if DEBUG_MODE and self.processed_packets <= 5:
                print(f"🔍 DEBUG: Packet {self.processed_packets} - src_addr: {src_addr}")

            if not src_addr:
                if DEBUG_MODE and self.processed_packets <= 5:
                    print(f"🔍 DEBUG: Packet {self.processed_packets} - No src_addr, returning")
                return
    
            src_addr = src_addr.lower()
            if DEBUG_MODE and self.processed_packets <= 5:
                    print(f"🔍 DEBUG: Packet {self.processed_packets} - src_addr lowered: {src_addr}")

            # Check if self.devices exists
            if not hasattr(self, 'devices'):
                if DEBUG_MODE:
                    print(f"🚨 CRITICAL: self.devices doesn't exist! Creating it...")
                self.devices = {}

            # Extract RSSI
            rssi = self._collect_rssi_data(packet, {})  # Pass empty dict temporarily for debug
            if DEBUG_MODE and self.processed_packets <= 5:
                print(f"🔍 DEBUG: Packet {self.processed_packets} - RSSI: {rssi}")

            # Get or create device
            if src_addr not in self.devices:
                if DEBUG_MODE:
                    print(f"✅ Creating device: {src_addr}")
                self.devices[src_addr] = self._create_device_entry(src_addr, packet)
        
            if DEBUG_MODE and self.processed_packets <= 5:
                print(f"🔍 DEBUG: Total devices so far: {len(self.devices)}")

            device = self.devices[src_addr]

            # Update basic device info
            device['packet_count'] += 1
            device['last_seen'] = self._get_packet_timestamp(packet)

            if rssi is not None:
                device['rssi_readings'].append(rssi)

            # ENHANCED PROCESSING BY FRAME TYPE
            if frame_type == 0:  # Management frames
                timestamp = self._get_packet_timestamp(packet)
                self._process_management_frame_enhanced(packet, bssid, device, timestamp)
            elif frame_type == 1:  # Control frames
                self._process_control_frame(packet, device, frame_subtype)
            elif frame_type == 2:  # Data frames
                self._process_data_frame_enhanced(packet, device, frame_subtype)

            # Update device metadata
            self._update_device_capabilities(packet, device)

        except Exception as e:
            if DEBUG_MODE:
                print(f"❌ EXCEPTION in _process_packet for packet {self.processed_packets}: {e}")
                import traceback
                print(traceback.format_exc())

    def _debug_device_status(self):
        """Debug method to check device status at any point"""
        print(f"\n🔍 DEBUG: Device Status Check")
        print(f"   Total devices: {len(getattr(self, 'devices', {}))}")
    
        if hasattr(self, 'devices') and self.devices:
            print(f"   Sample devices:")
            for i, (mac, device) in enumerate(list(self.devices.items())[:3]):
                print(f"     {i+1}. {mac}: {device.get('packet_count', 0)} packets, "
                      f"{len(device.get('rssi_readings', []))} RSSI, "
                      f"{len(device.get('security_events', []))} events")
        else:
            print(f"   ❌ No devices or devices dict doesn't exist!")
                
    def _check_security_events(self, packet, device, frame_type, frame_subtype):
        """Check for security-related events"""
        try:
            # Deauthentication frames (Management type=0, subtype=12)
            if frame_type == 0 and frame_subtype == 12:
                event = {
                    'type': 'deauthentication',
                    'timestamp': packet.sniff_time,
                    'source': device['mac_address'],
                    'target': getattr(packet.wlan, 'da', 'unknown')
                }
            device['security_events'].append(event)
            
            # Check for deauth flood (more than 20 deauths in 60 seconds)
            recent_deauths = [
                e for e in device['security_events'] 
                if e['type'] == 'deauthentication' 
                and (packet.sniff_time - e['timestamp']).total_seconds() < 60
            ]
            
            if len(recent_deauths) > 20:
                flood_event = {
                    'type': 'deauth_flood',
                    'timestamp': packet.sniff_time,
                    'source': device['mac_address'],
                    'count': len(recent_deauths)
                }
                device['security_events'].append(flood_event)
                print(f"SECURITY ALERT: Deauth flood detected from {device['mac_address']} ({len(recent_deauths)} deauths)")
        
            # Disassociation frames (Management type=0, subtype=10) 
            elif frame_type == 0 and frame_subtype == 10:
                event = {
                    'type': 'disassociation', 
                    'timestamp': packet.sniff_time,
                    'source': device['mac_address'],
                    'target': getattr(packet.wlan, 'da', 'unknown')
                }
                device['security_events'].append(event)
            
        except Exception as e:
            # Silently handle security event processing errors
            pass
    
    def _extract_radiotap(self, packet) -> tuple:
        """Extract radiotap physical layer information with fallback"""
        rssi = None
        channel = None
        data_rate = None
    
        if hasattr(packet, 'radiotap'):
            # Primary RSSI extraction methods
            rssi_fields = ['dbm_antsignal', 'db_antsignal']
            for field in rssi_fields:
                rssi_raw = getattr(packet.radiotap, field, None)
                if rssi_raw is not None:
                    try:
                        rssi = int(rssi_raw)
                        break
                    except (ValueError, TypeError):
                        continue
        
        # Channel extraction with multiple fallbacks
        channel_fields = ['channel.freq', 'freq', 'channel']
        for field in channel_fields:
            try:
                if '.' in field:
                    # Handle nested attributes like channel.freq
                    parts = field.split('.')
                    obj = packet.radiotap
                    for part in parts:
                        obj = getattr(obj, part, None)
                        if obj is None:
                            break
                    if obj is not None:
                        if field == 'channel.freq':
                            # Convert frequency to channel number
                            freq = int(obj)
                            if 2412 <= freq <= 2484:  # 2.4GHz band
                                channel = (freq - 2412) // 5 + 1
                            elif 5000 <= freq <= 6000:  # 5GHz band
                                channel = freq
                        else:
                            channel = int(obj)
                        break
                else:
                    channel_raw = getattr(packet.radiotap, field, None)
                    if channel_raw is not None:
                        channel = int(channel_raw)
                        break
            except (ValueError, TypeError, AttributeError):
                continue
        
        # Data rate extraction
        rate_fields = ['datarate', 'rate']
        for field in rate_fields:
            rate_raw = getattr(packet.radiotap, field, None)
            if rate_raw is not None:
                try:
                    data_rate = float(rate_raw)
                    break
                except (ValueError, TypeError):
                    continue
    
        return rssi, channel, data_rate
    
    def _extract_wlan_data(self, packet) -> tuple:
        """Extract 802.11 frame information"""
        bssid = getattr(packet.wlan, 'bssid', None)
        
        frame_info = {
            'src': getattr(packet.wlan, 'sa', None),
            'dst': getattr(packet.wlan, 'da', None),
            'type': getattr(packet.wlan, 'fc_type_subtype', None),
            'retry': getattr(packet.wlan, 'fc_retry', None)
        }
        
        return bssid, frame_info
    
    def _update_device(self, device: WiFiDeviceData, rssi: int, channel: int, 
                      frame_info: Dict, timestamp: str):
        """Update device with new packet information"""
        if rssi:
            device.rssi_readings.append(rssi)
        
        if channel and channel not in device.channels:
            device.channels.append(channel)
        
        if frame_info['type'] and frame_info['type'] not in device.frame_types:
            device.frame_types.append(frame_info['type'])
        
        device.last_seen = timestamp
    
    def _process_management_frame(self, packet, device, subtype):
        """Process management frame subtypes for additional information"""
        try:
            # Beacon frames (subtype 8) - Access Points
            if subtype == 8:
                device['is_access_point'] = True
            
                # Extract SSID from beacon
                if hasattr(packet, 'wlan_mgt'):
                    if hasattr(packet.wlan_mgt, 'ssid'):
                        ssid = getattr(packet.wlan_mgt, 'ssid', None)
                        if ssid and ssid.strip():
                            device['ssid'] = ssid
                
                    # Extract channel information
                    if hasattr(packet.wlan_mgt, 'ds_current_channel'):
                        device['channel'] = getattr(packet.wlan_mgt, 'ds_current_channel', None)
                    
            # Probe request frames (subtype 4) - Devices looking for networks
            elif subtype == 4:
                if hasattr(packet, 'wlan_mgt'):
                    if hasattr(packet.wlan_mgt, 'ssid'):
                        ssid = getattr(packet.wlan_mgt, 'ssid', None)
                        if ssid and ssid.strip():
                            device['probe_requests'].add(ssid)
                        
            # Association request (subtype 0)
            elif subtype == 0:
                device['frame_types'].add("association_request")
            
            # Association response (subtype 1) 
            elif subtype == 1:
                device['frame_types'].add("association_response")
            
        except Exception as e:
        # Silently handle management frame parsing errors
            pass
    
    def _determine_encryption(self, wlan_mgt) -> str:
        """Determine encryption type from management frame"""
        if hasattr(wlan_mgt, 'rsn'):
            return 'WPA2/WPA3'
        elif hasattr(wlan_mgt, 'wpa'):
            return 'WPA'
        elif getattr(wlan_mgt, 'capability_privacy', None) == '1':
            return 'WEP'
        else:
            return 'Open'
    
    def _detect_security_events(self, packet, frame_info: Dict, timestamp: str):
        """Detect security events in WiFi traffic"""
        # Deauthentication attack detection
        if frame_info['type'] in ['12', '10']:  # Deauth/Disassoc
            src = frame_info['src']
            if src:
                self.deauth_tracking[src].append(timestamp)
                self._check_deauth_attack(src, frame_info['dst'], timestamp)
    
    def _check_deauth_attack(self, src_addr: str, dst_addr: str, timestamp: str):
        """Check for deauthentication attacks"""
        recent_window = 60  # seconds
        attack_threshold = 20  # frames
        
        try:
            current_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            recent_deauths = [
                t for t in self.deauth_tracking[src_addr]
                if (current_time - datetime.fromisoformat(t.replace('Z', '+00:00'))).total_seconds() < recent_window
            ]
            
            if len(recent_deauths) >= attack_threshold:
                event = SecurityEvent(
                    event_type='deauth_attack',
                    severity='HIGH',
                    description=f'Deauth attack detected: {src_addr} sent {len(recent_deauths)} frames in {recent_window}s',
                    source=src_addr,
                    timestamp=timestamp,
                    evidence={
                        'target': dst_addr,
                        'frame_count': len(recent_deauths),
                        'time_window': recent_window
                    }
                )
                self.security_events.append(event)
        
        except Exception as e:
            logger.debug(f"ESP32: Error checking deauth attack: {e}")
    
    def _check_honeypot_activity(self, bssid: str, ssid: str, timestamp: str):
        """Monitor honeypot networks"""
        if ssid in self.honeypot_networks:
            severity = 'HIGH' if ssid == 'Admin_Network_Test' else 'MEDIUM'
            
            event = SecurityEvent(
                event_type='honeypot_activity',
                severity=severity,
                description=f'Activity on honeypot network: {ssid}',
                source=bssid,
                timestamp=timestamp,
                evidence={'network_type': 'honeypot', 'ssid': ssid}
            )
            self.security_events.append(event)
    
    def _post_process_analysis(self):
        """Post-processing analysis for additional threats"""
        self._detect_evil_twins()
        self._analyze_network_security()
    
    def _detect_evil_twins(self):
        """Detect potential evil twin access points"""
        ssid_groups = defaultdict(list)
        for device in self.devices.values():
            if device.ssid and not device.is_hidden:
                ssid_groups[device.ssid].append(device)
        
        for ssid, devices in ssid_groups.items():
            if len(devices) > 1:
                event = SecurityEvent(
                    event_type='evil_twin_detected',
                    severity='HIGH',
                    description=f'Multiple BSSIDs for SSID "{ssid}": potential evil twin',
                    source=ssid,
                    timestamp=datetime.now().isoformat(),
                    evidence={'bssids': [d.address for d in devices], 'count': len(devices)}
                )
                self.security_events.append(event)
    
    def _analyze_network_security(self):
        """Analyze overall network security posture"""
        open_networks = [d for d in self.devices.values() if d.encryption == 'Open']
        
        if len(open_networks) > 10:  # Threshold for suspicious number of open networks
            event = SecurityEvent(
                event_type='excessive_open_networks',
                severity='MEDIUM',
                description=f'High number of open networks detected: {len(open_networks)}',
                source='network_analysis',
                timestamp=datetime.now().isoformat(),
                evidence={'open_network_count': len(open_networks)}
            )
            self.security_events.append(event)

    def _extract_wlan_data_enhanced(self, packet) -> tuple:
        """Extract 802.11 frame information with enhanced field detection"""
        bssid = None
        
        # Multiple methods to extract BSSID
        bssid_fields = ['bssid', 'addr1', 'addr2', 'addr3']
        for field in bssid_fields:
            bssid_candidate = getattr(packet.wlan, field, None)
            if bssid_candidate and bssid_candidate != 'ff:ff:ff:ff:ff:ff':  # Skip broadcast
                bssid = bssid_candidate
                break
        
        # Enhanced frame information extraction
        frame_info = {
            'src': getattr(packet.wlan, 'sa', None),
            'dst': getattr(packet.wlan, 'da', None),
            'type': getattr(packet.wlan, 'fc_type_subtype', None),
            'retry': getattr(packet.wlan, 'fc_retry', None),
            'addr1': getattr(packet.wlan, 'addr1', None),
            'addr2': getattr(packet.wlan, 'addr2', None),
            'addr3': getattr(packet.wlan, 'addr3', None),
            'seq': getattr(packet.wlan, 'seq', None),
            'frag': getattr(packet.wlan, 'frag', None)
        }
        
        return bssid, frame_info

    def _update_device_enhanced(self, device: WiFiDeviceData, rssi: int, channel: int, 
                              data_rate: float, frame_info: Dict, timestamp: str):
        """Update device with enhanced data collection"""
        if rssi is not None:
            device.rssi_readings.append(rssi)
        
        if channel is not None and channel not in device.channels:
            device.channels.append(channel)
        
        if frame_info.get('type') and frame_info['type'] not in device.frame_types:
            device.frame_types.append(frame_info['type'])
        
        # Track additional frame information
        if frame_info.get('seq'):
            # Could track sequence numbers for analysis
            pass
        
        device.last_seen = timestamp

    def _process_management_frame_enhanced(self, packet, bssid, device: WiFiDeviceData, timestamp: str):
        """Process WiFi management frames with enhanced extraction"""
        try:
            # Multiple ways to access management frame data
            wlan_mgt = None
            if hasattr(packet, 'wlan_mgt'):
                wlan_mgt = packet.wlan_mgt
            elif hasattr(packet, 'wlan') and hasattr(packet.wlan, 'mgt'):
                wlan_mgt = packet.wlan.mgt
            
            if wlan_mgt:
                # Enhanced SSID extraction
                ssid = self._extract_ssid_enhanced(wlan_mgt)
                if ssid:
                    device.ssid = ssid
                    device.is_hidden = False
                elif not device.ssid:  # Only mark as hidden if we haven't found SSID yet
                    device.is_hidden = True
                
                # Enhanced security information
                device.encryption = self._determine_encryption_enhanced(wlan_mgt)
                
                # Extract additional management frame details
                beacon_interval = getattr(wlan_mgt, 'beacon', None) or getattr(wlan_mgt, 'beacon_interval', None)
                if beacon_interval:
                    try:
                        device.beacon_interval = int(beacon_interval)
                    except (ValueError, TypeError):
                        pass
                
                # Country code extraction
                country_fields = ['country_info_code', 'country', 'country_code']
                for field in country_fields:
                    country = getattr(wlan_mgt, field, None)
                    if country:
                        device.country_code = str(country)
                        break
                
                # Check honeypot activity with enhanced detection
                self._check_honeypot_activity_enhanced(device.address, device.ssid, timestamp)
        
        except Exception as e:
            logger.debug(f"ESP32: Error processing management frame: {e}")

    def _extract_ssid_enhanced(self, wlan_mgt) -> Optional[str]:
        """Enhanced SSID extraction with multiple fallback methods"""
        ssid_fields = ['ssid', 'tag_ssid', 'ie_ssid', 'ssid_value']
        
        for field in ssid_fields:
            ssid = getattr(wlan_mgt, field, None)
            if ssid:
                try:
                    # Handle different SSID encodings
                    if isinstance(ssid, str):
                        if ':' in ssid and len(ssid) > 10:  # Hex encoded
                            ssid_bytes = bytes.fromhex(ssid.replace(':', ''))
                            return ssid_bytes.decode('utf-8', errors='ignore')
                        else:
                            return ssid
                    elif hasattr(ssid, 'decode'):
                        return ssid.decode('utf-8', errors='ignore')
                    else:
                        return str(ssid)
                except (ValueError, UnicodeDecodeError, AttributeError):
                    continue
        
        return None
    
    def _extract_ssid(self, packet):
        """Simple wrapper for enhanced SSID extraction"""
        if hasattr(packet, 'wlan_mgt'):
            return self._extract_ssid_enhanced(packet.wlan_mgt)
        return None

    def _determine_encryption_enhanced(self, wlan_mgt) -> str:
        """Enhanced encryption type determination"""
        # Check for WPA3/WPA2
        if hasattr(wlan_mgt, 'rsn') or hasattr(wlan_mgt, 'rsn_ie'):
            return 'WPA2/WPA3'
        
        # Check for WPA
        if hasattr(wlan_mgt, 'wpa') or hasattr(wlan_mgt, 'wpa_ie'):
            return 'WPA'
        
        # Check for WEP via capability bits
        capability_fields = ['capability_privacy', 'cap_privacy', 'privacy']
        for field in capability_fields:
            privacy = getattr(wlan_mgt, field, None)
            if privacy == '1' or privacy == 1 or privacy is True:
                return 'WEP'
        
        return 'Open'

    def _get_network_statistics(self) -> Dict[str, Any]:
        """Get comprehensive network statistics with enhanced RSSI analysis"""
        base_stats = self.get_statistics()
        
        # Enhanced RSSI statistics
        all_rssi = []
        rssi_by_device = {}
        channel_distribution = defaultdict(int)
        encryption_distribution = defaultdict(int)
        
        for bssid, device in self.devices.items():
            if device.rssi_readings:
                all_rssi.extend(device.rssi_readings)
                rssi_by_device[bssid] = {
                    'ssid': device.ssid or 'Hidden',
                    'min_rssi': min(device.rssi_readings),
                    'max_rssi': max(device.rssi_readings),
                    'avg_rssi': sum(device.rssi_readings) / len(device.rssi_readings),
                    'rssi_count': len(device.rssi_readings)
                }
            
            for channel in device.channels:
                channel_distribution[channel] += 1
            
            encryption_distribution[device.encryption or 'Unknown'] += 1
        
        # Calculate comprehensive RSSI statistics
        rssi_stats = {}
        if all_rssi:
            rssi_stats = {
                'total_measurements': len(all_rssi),
                'min_rssi': min(all_rssi),
                'max_rssi': max(all_rssi),
                'avg_rssi': round(sum(all_rssi) / len(all_rssi), 2),
                'rssi_distribution': {
                    'excellent_(-30_to_0)': len([r for r in all_rssi if r >= -30]),
                    'very_good_(-50_to_-30)': len([r for r in all_rssi if -50 <= r < -30]),
                    'good_(-60_to_-50)': len([r for r in all_rssi if -60 <= r < -50]),
                    'fair_(-70_to_-60)': len([r for r in all_rssi if -70 <= r < -60]),
                    'weak_(-80_to_-70)': len([r for r in all_rssi if -80 <= r < -70]),
                    'very_weak_(<-80)': len([r for r in all_rssi if r < -80])
                },
                'strongest_signals': sorted([
                    {'bssid': bssid, 'ssid': data['ssid'], 'max_rssi': data['max_rssi']}
                    for bssid, data in rssi_by_device.items()
                ], key=lambda x: x['max_rssi'], reverse=True)[:10]
            }
        
        wifi_stats = {
            'rssi_analysis': rssi_stats,
            'network_analysis': {
                'total_networks_detected': len(self.devices),
                'networks_with_rssi_data': len(rssi_by_device),
                'hidden_networks': len([d for d in self.devices.values() if d.is_hidden]),
                'open_networks': len([d for d in self.devices.values() if d.encryption == 'Open']),
                'channel_distribution': dict(channel_distribution),
                'encryption_distribution': dict(encryption_distribution)
            },
            'device_intelligence': {
                'devices_by_signal_strength': rssi_by_device,
                'most_active_channels': sorted(channel_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
            }
        }
        
        return {**base_stats, **wifi_stats}
    
    def _check_honeypot_activity_enhanced(self, bssid: str, ssid: str, timestamp: str):
        """Enhanced monitoring of honeypot networks with detailed analysis"""
        if ssid and ssid in self.honeypot_networks:
            severity = 'HIGH' if ssid == 'Admin_Network_Test' else 'MEDIUM'
            
            event = SecurityEvent(
                event_type='honeypot_activity',
                severity=severity,
                description=f'Enhanced honeypot activity detected on network: {ssid}',
                source=bssid,
                timestamp=timestamp,
                evidence={
                    'network_type': 'honeypot',
                    'ssid': ssid,
                    'bssid': bssid,
                    'risk_level': severity.lower()
                }
            )
            self.security_events.append(event)
            logger.warning(f"Honeypot activity detected: {ssid} ({bssid})")


    """
    Safe Data Compression Implementation
    Removes unnecessary fields while preserving all essential analysis data
    """

    def _compress_device_data(self, devices):
        """
        Compress device data by removing unnecessary fields and optimizing data structures
        This is called just before returning AnalysisResult
        """
        compressed_devices = {}

        for mac, device in devices.items():
            compressed_device = {}
    
            # Essential device information (always keep)
            essential_fields = [
                'mac_address', 'bssid', 'first_seen', 'last_seen', 
                'packet_count', 'ssid', 'is_hidden', 'is_access_point', 
                'channel', 'encryption'
            ]
    
            for field in essential_fields:
                if field in device:
                    compressed_device[field] = device[field]
    
            # Convert sets to lists for JSON serialization
            if 'frame_types' in device:
                if isinstance(device['frame_types'], set):
                    compressed_device['frame_types'] = sorted(list(device['frame_types']))
                else:
                    compressed_device['frame_types'] = device['frame_types']
    
            if 'probe_requests' in device:
                if isinstance(device['probe_requests'], set):
                    compressed_device['probe_requests'] = sorted(list(device['probe_requests']))
                else:
                    compressed_device['probe_requests'] = device['probe_requests']
    
            # Security events (keep all - this is critical data)
            if 'security_events' in device:
                compressed_device['security_events'] = device['security_events']
    
            # RSSI Data Compression
            rssi_readings = device.get('rssi_readings', [])
            signal_strengths = device.get('signal_strengths', [])
            primary_rssi = rssi_readings if len(rssi_readings) >= len(signal_strengths) else signal_strengths
    
            if primary_rssi:
                compressed_device['rssi_statistics'] = self._calculate_rssi_statistics(primary_rssi)
                compressed_device['rssi_samples'] = {
                    'first_5': primary_rssi[:5],
                    'last_5': primary_rssi[-5:],
                    'total_count': len(primary_rssi)
                }
            else:
                compressed_device['rssi_statistics'] = {
                    'count': 0, 'avg': None, 'max': None, 'min': None, 'samples': []
                }
    
            compressed_devices[mac] = compressed_device

        return compressed_devices

    def _calculate_rssi_statistics(self, rssi_readings):
        """
        Calculate comprehensive RSSI statistics from readings array
        Replaces large arrays with computed statistics
        """
        if not rssi_readings:
            return {
                'count': 0,
                'avg': None,
                'max': None,
                'min': None,
                'median': None,
                'std_dev': None,
                'range': None,
                'trend': 'unknown',
                'signal_quality': 'unknown'
            }
    
        try:
            import statistics
        
            count = len(rssi_readings)
            avg_rssi = statistics.mean(rssi_readings)
            max_rssi = max(rssi_readings)
            min_rssi = min(rssi_readings)
            median_rssi = statistics.median(rssi_readings)
        
            # Calculate standard deviation if enough samples
            std_dev = statistics.stdev(rssi_readings) if count > 1 else 0
        
            # Calculate range
            signal_range = max_rssi - min_rssi
        
            # Trend analysis (simple slope of first and last values)
            trend = "stable"
            if count > 10:  # Only analyze trend with sufficient data
                first_quarter = statistics.mean(rssi_readings[:count//4]) if count >= 4 else rssi_readings[0]
                last_quarter = statistics.mean(rssi_readings[-count//4:]) if count >= 4 else rssi_readings[-1]
                iff = last_quarter - first_quarter
                if iff > 3:
                    trend = "improving"  # Signal getting stronger
                elif iff < -3:
                    trend = "degrading"  # Signal getting weaker
        
            # Signal quality assessment
            signal_quality = "unknown"
            if avg_rssi > -30:
                signal_quality = "excellent"
            elif avg_rssi > -50:
                signal_quality = "very_good"
            elif avg_rssi > -60:
                signal_quality = "good"
            elif avg_rssi > -70:
                signal_quality = "fair"
            elif avg_rssi > -80:
                signal_quality = "poor"
            else:
                signal_quality = "very_poor"
        
            return {
                'count': count,
                'avg': round(avg_rssi, 2),
                'max': max_rssi,
                'min': min_rssi,
                'median': round(median_rssi, 2),
                'std_dev': round(std_dev, 2),
                'range': signal_range,
                'trend': trend,
                'signal_quality': signal_quality,
                # Mini-sparkline: strategic sample points for visualization
                'sparkline': {
                    'first': rssi_readings[0],
                    'quarter_1': rssi_readings[count//4] if count >= 4 else rssi_readings[0],
                    'median_point': rssi_readings[count//2] if count >= 2 else rssi_readings[0],
                    'quarter_3': rssi_readings[3*count//4] if count >= 4 else rssi_readings[-1],
                    'last': rssi_readings[-1]
                }
            }
        
        except Exception as e:
            return {
                'count': len(rssi_readings),
                'error': str(e),
                'avg': sum(rssi_readings) / len(rssi_readings) if rssi_readings else 0,
                'max': max(rssi_readings) if rssi_readings else None,
                'min': min(rssi_readings) if rssi_readings else None
            }

    def _remove_debug_fields(self, devices):
        """
        Remove debug and unnecessary fields that bloat the JSON
        """
        fields_to_remove = [
            'frame_raw',           # Full hex payload - keep in PCAP, not JSON
            'raw_packet_data',     # Raw packet bytes
            'debug_info',          # Debug information
            'parser_metadata',     # Parser-specific metadata
            'radiotap_flags',      # Radiotap flags (keep only dbm_antsignal)
            'radiotap_antenna',    # Antenna info
            'radiotap_mactime',    # MAC timestamp
            'radiotap_data_rate',  # Data rate (rarely changes analysis)
            'wlan_mgt_tags_raw',   # Raw management frame tags
            'eir_ad_raw',          # Raw BLE advertisement data
            'capture_metadata'     # Per-packet capture info
        ]
    
        cleaned_devices = {}
        for mac, device in devices.items():
            cleaned_device = {}
            for key, value in device.items():
                if key not in fields_to_remove:
                    cleaned_device[key] = value
            cleaned_devices[mac] = cleaned_device
    
        return cleaned_devices

    def _optimize_security_events(self, devices):
        """
        Optimize security events storage while preserving all critical information
        """
        for mac, device in devices.items():
            security_events = device.get('security_events', [])
            if security_events:
                # Keep all security events but optimize their structure
                optimized_events = []
                for event in security_events:
                    optimized_event = {
                        'type': event.get('type'),
                        'timestamp': event.get('timestamp'),
                        'source': event.get('source'),
                        'target': event.get('target', 'unknown')
                    }
                
                    # Only include non-default values
                    if event.get('reason') and event.get('reason') != 'unknown':
                        optimized_event['reason'] = event.get('reason')
                
                    if event.get('count'):  # For flood events
                        optimized_event['count'] = event.get('count')
                
                    optimized_events.append(optimized_event)
            
                device['security_events'] = optimized_events
    
        return devices
    
    def _aggregate_security_events(self):
        """
        Bubble up device-level security events to file and summary level
        This fixes the "security_event_count: 0" issue
        """
        total_security_events = 0
        security_event_types = {}
        high_risk_devices = []
    
        # Count events from all devices
        for mac, device in self.devices.items():
            device_events = device.get('security_events', [])
            device_event_count = len(device_events)
            total_security_events += device_event_count
        
            # Track event types
            for event in device_events:
                event_type = event.get('type', 'unknown')
                security_event_types[event_type] = security_event_types.get(event_type, 0) + 1
        
            # Identify high-risk devices
            if device_event_count >= 10:  # Devices with many security events
                high_risk_devices.append({
                    'mac': mac,
                    'event_count': device_event_count,
                    'event_types': list(set(e.get('type') for e in device_events))
                })
    
        # Store aggregated data
        self.aggregated_security_stats = {
            'total_events': total_security_events,
            'event_types': security_event_types,
            'high_risk_devices': high_risk_devices,
            'devices_with_events': len([d for d in self.devices.values() if d.get('security_events')])
        }
    
        # Calculate risk level
        risk_level = self._calculate_risk_level(total_security_events, security_event_types)
        self.current_risk_level = risk_level
    
        print(f"🚨 SECURITY AGGREGATION: {total_security_events} total events, risk level: {risk_level}")
    
        return total_security_events, risk_level

    def _calculate_risk_level(self, total_events, event_types):
        """
        Calculate overall risk level based on security events
        """
        if total_events == 0:
            return 'LOW'
    
        # Count critical event types
        deauth_events = event_types.get('deauthentication', 0)
        deauth_floods = event_types.get('deauth_flood', 0)
        disassoc_events = event_types.get('disassociation', 0)
    
        # Risk thresholds
        if deauth_floods > 0 or deauth_events > 100:
            return 'CRITICAL'
        elif deauth_events > 20 or disassoc_events > 10:
            return 'HIGH'
        elif total_events > 5:
            return 'MEDIUM'
        else:
            return 'LOW'
        
    def _get_packet_timestamp(self, packet):
        """Get packet timestamp with proper formatting"""
        try:
            if hasattr(packet, 'sniff_time'):
                return packet.sniff_time.isoformat() + 'Z'
            elif hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'time_epoch'):
                epoch_time = float(packet.frame_info.time_epoch)
                from datetime import datetime
                return datetime.utcfromtimestamp(epoch_time).isoformat() + 'Z'
            else:
                from datetime import datetime
                return datetime.utcnow().isoformat() + 'Z'
        except Exception as e:
            from datetime import datetime
            return datetime.utcnow().isoformat() + 'Z'

    # FIX 2: Timestamp Conversion Fix
    def _fix_packet_timestamp(self, packet):
        """
        Convert packet timestamp from epoch to proper datetime
        Fixes the 1969-12-31 timestamp issue
        """
        try:
            # Get timestamp from packet
            if hasattr(packet, 'sniff_time'):
                # PyShark already provides datetime object
                return packet.sniff_time
            elif hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'time_epoch'):
                # Convert epoch timestamp
                epoch_time = float(packet.frame_info.time_epoch)
                return datetime.utcfromtimestamp(epoch_time)
            elif hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'time'):
                # Parse time string
                time_str = packet.frame_info.time
                return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
            else:
                # Fallback to current time
                return datetime.utcnow()
        except Exception as e:
            # If timestamp parsing fails, use current time
            print(f"⚠️  Timestamp parsing error: {e}, using current time")
            return datetime.utcnow()

    # FIX 3: Enhanced RSSI Collection
    def _collect_rssi_data(self, packet, device):
        """
        Improved RSSI collection from radiotap header
        Ensures RSSI data reaches device statistics
        """
        rssi_value = None
    
        # Multiple methods to extract RSSI
        try:
            # Method 1: Direct radiotap access
            if hasattr(packet, 'radiotap'):
                if hasattr(packet.radiotap, 'dbm_antsignal'):
                    rssi_value = int(packet.radiotap.dbm_antsignal)
                elif hasattr(packet.radiotap, 'db_antsignal'):
                    rssi_value = int(packet.radiotap.db_antsignal)
        
            # Method 2: Check for signal strength in other locations
            if rssi_value is None and hasattr(packet, 'wlan_radio'):
                if hasattr(packet.wlan_radio, 'signal_dbm'):
                    rssi_value = int(packet.wlan_radio.signal_dbm)
        
            # Method 3: Frame-level signal info
            if rssi_value is None and hasattr(packet, 'frame'):
                if hasattr(packet.frame, 'signal_dbm'):
                    rssi_value = int(packet.frame.signal_dbm)
        
            # Add RSSI to device if found
            if rssi_value is not None:
                if 'signal_strengths' not in device:
                    device['signal_strengths'] = []
                if 'rssi_readings' not in device:
                    device['rssi_readings'] = []
                
                device['signal_strengths'].append(rssi_value)
                device['rssi_readings'].append(rssi_value)
            
                return rssi_value
    
        except Exception as e:
            # Silently handle RSSI extraction errors
            pass
    
        return None

    # INTEGRATION: Modified _process_packet method with fixes
    #def _process_packet_with_fixes(self, packet):
        #""" Process a single packet with critical fixes applied """
        #try:
            #if not hasattr(packet, 'wlan'):
            #    return
    
            # FIX 2: Get proper timestamp
            #packet_timestamp = self._fix_packet_timestamp(packet)
    
            # ... existing frame control parsing code ...
        
            # Extract addresses
            #src_addr = getattr(packet.wlan, 'sa', None)
            #if not src_addr:
            #    return
        
            # Create or update device entry
            #device_key = src_addr.lower()
            #if device_key not in self.devices:
            #    self.devices[device_key] = {
            #        'mac_address': src_addr,
            #        'bssid': getattr(packet.wlan, 'bssid', None),
            #        'first_seen': packet_timestamp,  # FIX 2: Use corrected timestamp
            #        'last_seen': packet_timestamp,   # FIX 2: Use corrected timestamp
            #        'packet_count': 0,
            #        'signal_strengths': [],
            #        'rssi_readings': [],
            #        'frame_types': set(),
            #        'security_events': [],
            #        'ssid': None,
            #        'is_hidden': False,
            #        'is_access_point': False,
            #        'channel': None,
            #        'encryption': None,
            #        'probe_requests': set()
            #    }
    
            # Update device info
            #device = self.devices[device_key]
            #device['last_seen'] = packet_timestamp  # FIX 2: Use corrected timestamp
            #device['packet_count'] += 1
    
            # ... existing frame type and security event detection code ...
        
            # FIX 3: Enhanced RSSI collection
            #rssi_value = self._collect_rssi_data(packet, device)
            #if rssi_value:
                # RSSI successfully collected and added to device
            #    pass
        
        #except Exception as e:
        #    print(f"❌ Error in packet processing: {e}")

    # INTEGRATION: Modified compression method to include aggregation
    def compress_and_optimize_data(self):
        print(f"🔍 COMPRESSION DEBUG: Starting with {len(self.devices)} devices")
        """
        Enhanced compression with security event aggregation
        """
        print(f"🗜️  COMPRESSION: Starting data optimization with fixes...")
    
        # FIX 1: Aggregate security events BEFORE compression
        total_events, risk_level = self._aggregate_security_events()
    
        # Original compression steps
        original_device_count = len(self.devices)
        self.devices = self._remove_debug_fields(self.devices)
        # self.devices = self._optimize_security_events(self.devices)  # ✅ Fixed line
        self.devices = self._compress_device_data(self.devices)
        self.devices = self.add_proximity_analysis_to_device_data(self.devices)
    
        print(f"🗜️  COMPRESSION: Complete! {original_device_count} devices, {total_events} security events, risk: {risk_level}")

    # INTEGRATION: Enhanced AnalysisResult with aggregated data
    def create_analysis_result_with_fixes(self, file_path):
        """
        Create AnalysisResult with proper security event aggregation
        """
        print(f"🔧 DEBUG: Creating AnalysisResult...")
        print(f"   Input devices: {len(self.devices)}")
    
        # Get aggregated security stats
        security_stats = getattr(self, 'aggregated_security_stats', {
            'total_events': 0,
            'event_types': {},
            'high_risk_devices': [],
            'devices_with_events': 0
        })
    
        print(f"   Security stats: {security_stats.get('total_events', 0)} events")
    
        risk_level = getattr(self, 'current_risk_level', 'LOW')
    
        result = AnalysisResult(
            protocol='WiFi',
            capture_source='ESP32',
            devices=self.devices,  # ← CHECK IF THIS IS STILL 162 devices
            security_events=self.security_events,
            statistics={
                **self.get_statistics(),
                'security_event_count': security_stats['total_events'],
                'security_event_types': security_stats['event_types'],
                'high_risk_devices': security_stats['high_risk_devices'],
                'risk_level': risk_level,
                'devices_with_security_events': security_stats['devices_with_events']
            },
            metadata={
                'file_path': file_path, 
                'adapter': 'ESP32WiFiAdapter',
                'compressed': True,
                'fixes_applied': ['timestamp_conversion', 'security_aggregation', 'enhanced_rssi']
            }
        )
    
        print(f"   AnalysisResult created with {len(result.devices)} devices")
        print(f"🔍 RESULT DEBUG: result.devices has {len(result.devices)} devices")
        if hasattr(result.devices, 'items'):
            print(f"   First device: {list(result.devices.keys())[0] if result.devices else 'NONE'}")
        return result

    # INTEGRATION METHOD - Add this to your ESP32WiFiAdapter class

    # TESTING - Before/After Size Comparison
    def estimate_compression_savings():
        """
        Rough estimation of compression savings
        """
        print("📊 ESTIMATED COMPRESSION SAVINGS:")
        print("   RSSI Arrays: 162 devices × 8000 readings × 4 bytes = ~5MB")
        print("   RSSI Statistics: 162 devices × 200 bytes = ~32KB") 
        print("   💾 RSSI Compression: ~99% reduction")
        print("   🗑️  Debug Field Removal: ~10-20% additional reduction")
        print("   🎯 Total Expected: 50-70% smaller JSON files")

    def _make_json_serializable(self, obj):
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, set):
            return list(obj)
        elif hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):  # Complex objects
            return str(obj)
        else:
            return obj
        
# =============================================================================
# BLUETOOTH ADAPTER (nRF)
# =============================================================================

class nRFBluetoothAdapter(CaptureAdapter):
    """Adapter for nRF Bluetooth captures"""

    import logging
    print("🔍 DEBUG: nRF adapter loaded")
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.connection_tracking = defaultdict(list)
    
    def can_handle(self, file_path: str) -> bool:
        """Check if file is a nRF Bluetooth capture"""
        filename = Path(file_path).name.lower()
        return any(pattern in filename for pattern in ['nrf', 'bluetooth', 'ble'])
    
    def get_device_type(self) -> type:
        """Return Bluetooth device data type"""
        return BluetoothDeviceData
    
    def parse_file(self, file_path: str) -> AnalysisResult:
        """Parse nRF Bluetooth PCAP file"""
        logger.info(f"nRF Adapter: Parsing {file_path}")
        self.reset_statistics()
        
        MAX_PACKETS = None  # < ------- Adjust to analyze number of packets None to analyze all -----

        try:
            capture = pyshark.FileCapture(
                file_path,
                display_filter='bthci_evt or btle or btcommon',
                include_raw=True,
                use_json=True
            )
            
            for packet in capture:
                self._process_packet(packet)
                self.processed_packets += 1

                if MAX_PACKETS and self.processed_packets >= MAX_PACKETS:
                    logger.info(f"🐛 nRF DEBUG: Stopping at {MAX_PACKETS} packets for testing")
                    break
                
                if self.processed_packets % 5000 == 0:
                    logger.info(f"nRF: Processed {self.processed_packets} packets")
            
            capture.close()
            self._post_process_analysis()

            compressed_devices = self._compress_device_data(self.devices)
            
            return AnalysisResult(
                protocol='Bluetooth',
                capture_source='nRF',
                devices=compressed_devices,
                security_events=self.security_events,
                statistics=self.get_statistics(),
                metadata={'file_path': file_path, 'adapter': 'nRFBluetoothAdapter'}
            )
            
        except Exception as e:
            logger.error(f"nRF Adapter error: {e}")
            return AnalysisResult(
                protocol='Bluetooth',
                capture_source='nRF',
                devices={},
                security_events=[],
                statistics={'error': str(e)},
                metadata={'file_path': file_path, 'error': True}
            )
    
    def _process_packet(self, packet):
        """Process individual Bluetooth packet"""
        try:
            
            timestamp = str(packet.sniff_time)
            
            # Process BLE advertisements
            if hasattr(packet, 'btle'):
                address = self._extract_bluetooth_address(packet.btle)
                if address:
                    self._process_ble_packet(packet, address, timestamp)
            
            # Process HCI events
            elif hasattr(packet, 'bthci_evt'):
                self._process_hci_event(packet, timestamp)
        
        except Exception as e:
            logger.debug(f"nRF: Error processing packet: {e}")


        # REMOVE after debugging RSSI Bluetooth data        

    #def _debug_bluetooth_packet_fields(self, packet):
        #"""Debug method to see available fields in Nordic nRF Bluetooth packets"""
        #DEBUG_MODE = True  # Set to False to turn off
    
        #if DEBUG_MODE and self.processed_packets <= 10:
            #print(f"\n🔍 NORDIC nRF PACKET {self.processed_packets} DEBUG:")
        
            # Check all available layers
            #print(f"   Available layers: {[layer.layer_name for layer in packet.layers]}")
        
            # Check for Nordic-specific layers
            #for layer_name in ['nordic_ble', 'nrf_sniffer', 'nrf', 'frame', 'radiotap']:
                #if hasattr(packet, layer_name):
                    #layer = getattr(packet, layer_name)
                    #print(f"   🎯 {layer_name} layer found!")
                
                    # Look for RSSI/signal fields
                    #all_fields = [f for f in dir(layer) if not f.startswith('_')]
                    #signal_fields = [f for f in all_fields if any(keyword in f.lower() for keyword in ['rssi', 'signal', 'dbm', 'strength', 'power'])]
                
                    #if signal_fields:
                        #print(f"     🎉 Signal fields found: {signal_fields}")
                        #for field in signal_fields:
                            #try:
                                #value = getattr(layer, field)
                                #print(f"       {layer_name}.{field}: {value}")
                            #except:
                                #print(f"       {layer_name}.{field}: <error accessing>")
                    #else:
                        #print(f"     All fields: {all_fields[:15]}...")  # Show first 15
        
            # Check BTLE layer for any missed fields
            #if hasattr(packet, 'btle'):
                #print(f"   BTLE layer fields:")
                #btle_fields = [f for f in dir(packet.btle) if not f.startswith('_')]
                #for field in btle_fields[:10]:
                    #try:
                        #value = getattr(packet.btle, field)
                        #print(f"     btle.{field}: {value}")
                    #except:
                        #pass

        # End of DEBUG #
    
    def _extract_bluetooth_address(self, btle_layer) -> Optional[str]:
        """Extract Bluetooth address from various fields"""
        for field in ['advertising_address', 'master', 'slave', 'initiator', 'advertiser']:
            address = getattr(btle_layer, field, None)
            if address:
                return address
        return None
    
    def _process_ble_packet(self, packet, address: str, timestamp: str):
        """Process BLE advertisement packet"""
        # Initialize device if new
        if address not in self.devices:
            self.devices[address] = BluetoothDeviceData(
                address=address,
                first_seen=timestamp,
                is_random_address=self._is_random_address(address)
            )
        
        device = self.devices[address]
        
        # Extract RSSI
        rssi = getattr(packet.nordic_ble, 'rssi', None) if hasattr(packet, 'nordic_ble') else None
        if rssi:
            device.rssi_readings.append(int(rssi))
        
        # Extract address type
        address_type = getattr(packet.btle, 'address_type', None)
        if address_type:
            device.address_type = address_type
        
        device.last_seen = timestamp

        # Extract advertising data (enhanced to include btle.advertising_data)
        self._extract_advertising_data(packet, device)
    
        # Extract advertising data
        if hasattr(packet, 'btcommon'):
            self._extract_advertising_data(packet, device)
    
    def _extract_advertising_data(self, packet, device: BluetoothDeviceData):
        """Extract information from Bluetooth advertising data"""
        DEBUG_MODE = False  # Set to False to turn off debug
    
        try:
            # Extract from btle.advertising_data (new source - richer data)
            if hasattr(packet, 'btle') and hasattr(packet.btle, 'advertising_data'):
                self._extract_btle_advertising_data(packet.btle.advertising_data, device, DEBUG_MODE)
        
            # Keep existing btcommon extraction for compatibility
            if hasattr(packet, 'btcommon'):
                if hasattr(packet.btcommon, 'eir_ad'):
                    # Extract device name
                    for field_name in dir(packet.btcommon.eir_ad):
                        if 'device_name' in field_name.lower() or 'local_name' in field_name.lower():
                            name = getattr(packet.btcommon.eir_ad, field_name, None)
                            if name and not device.name:
                                device.name = str(name)
                            break
                
                    # Extract manufacturer and services
                    if hasattr(packet.btcommon.eir_ad, 'entry'):
                        self._process_eir_entries(packet.btcommon.eir_ad.entry, device)
    
        except Exception as e:
            logger.debug(f"nRF: Error extracting advertising data: {e}")
            if DEBUG_MODE:
                print(f"🚨 Advertising data extraction error: {e}")

    def _extract_btle_advertising_data(self, advertising_data, device: BluetoothDeviceData, debug_mode=True):
        """Extract data from btle.advertising_data layer"""
        try:
            # Store raw data for debugging
            if debug_mode:
                device.raw_advertising_data = str(advertising_data)[:200]  # First 200 chars
        
            # Check if entry exists and process first/primary entry
            if hasattr(advertising_data, 'entry'):
                entry = advertising_data.entry
    
                # Handle multiple entries - get first one
                if hasattr(entry, '__iter__') and not isinstance(entry, str):
                    try:
                        entry = list(entry)[0]  # Get first entry
                    except:
                        entry = None  # Set to None if we can't get first entry
    
                # Only proceed if we have a valid entry
                if entry is None:
                    return
            
                # Extract device name
                if hasattr(entry, 'device_name'):
                    device_name = str(entry.device_name).strip()
                    if device_name and device_name != 'None':
                        device.name = device_name
                        if debug_mode:
                            print(f"📱 Device name extracted: {device_name}")
            
                # Extract company ID and map to manufacturer
                if hasattr(entry, 'company_id'):
                    company_id = str(entry.company_id)
                    device.company_id = company_id
                    device.manufacturer = self._map_company_id_to_name(company_id)
                    if debug_mode:
                        print(f"🏢 Company: {company_id} -> {device.manufacturer}")
            
                # Extract power level
                if hasattr(entry, 'power_level'):
                    try:
                        device.power_level = int(entry.power_level)
                        if debug_mode:
                            print(f"⚡ Power level: {device.power_level} dBm")
                    except:
                        pass
        
            # Extract privacy/randomization info from packet
            if hasattr(advertising_data, '_parent') and hasattr(advertising_data._parent, 'advertising_header_tree'):
                header = advertising_data._parent.advertising_header_tree
                if hasattr(header, 'randomized_tx'):
                    device.privacy_enabled = bool(int(header.randomized_tx))
                    if debug_mode and device.privacy_enabled:
                        print(f"🔒 Privacy enabled (randomized MAC)")
        
            # Store debug info
            if debug_mode:
                device.extraction_debug_info = {
                    'btle_advertising_data_found': True,
                    'entry_type': type(entry).__name__,
                    'available_fields': [f for f in dir(entry) if not f.startswith('_')][:10]
                }
    
        except Exception as e:
            if debug_mode:
                print(f"🚨 BTLE advertising extraction error: {e}")
            device.extraction_debug_info = {'error': str(e)}

    def _map_company_id_to_name(self, company_id):
        """Map Bluetooth company IDs to manufacturer names"""
        company_map = {
            '0x004c': 'Apple',
            '0x014c': 'Apple',
            '0x0006': 'Microsoft',
            '0x000f': 'Broadcom',
            '0x0075': 'Samsung',
            '0x01d7': 'Qualcomm',
            '0x0059': 'Nordic Semiconductor',
            '0x0087': 'Garmin',
            '0x004f': 'Nokia'
        }
        return company_map.get(company_id, f'Unknown ({company_id})')
    
    def _process_eir_entries(self, eir_entry, device: BluetoothDeviceData):
        """Process EIR (Extended Inquiry Response) entries"""
        try:
            entries = eir_entry.all_fields if hasattr(eir_entry, 'all_fields') else [eir_entry]
            
            for entry in entries:
                if hasattr(entry, 'type'):
                    entry_type = str(getattr(entry, 'type', ''))
                    
                    if 'manufacturer' in entry_type.lower():
                        device.manufacturer = getattr(entry, 'company', 'Unknown')
                    elif 'service' in entry_type.lower():
                        service_uuid = getattr(entry, 'uuid', None)
                        if service_uuid and service_uuid not in device.services:
                            device.services.append(service_uuid)
                    elif 'device_name' in entry_type.lower() or 'local_name' in entry_type.lower():
                        if not device.name:
                            device.name = getattr(entry, 'value', '')
        
        except Exception as e:
            logger.debug(f"nRF: Error processing EIR entries: {e}")
    
    def _process_hci_event(self, packet, timestamp: str):
        """Process HCI events"""
        try:
            event_code = getattr(packet.bthci_evt, 'code', None)
            
            if event_code in ['0x03', '0x05']:  # Connection/Disconnection events
                event = SecurityEvent(
                    event_type='bluetooth_connection_event',
                    severity='INFO',
                    description=f'Bluetooth connection event: {event_code}',
                    source='HCI',
                    timestamp=timestamp,
                    evidence={'event_code': event_code}
                )
                self.security_events.append(event)
        
        except Exception as e:
            logger.debug(f"nRF: Error processing HCI event: {e}")
    
    def _is_random_address(self, address: str) -> bool:
        """Check if address is random (privacy feature)"""
        try:
            first_octet = int(address.split(':')[0], 16)
            return (first_octet & 0xC0) in [0xC0, 0x40]
        except:
            return False
    
    def _post_process_analysis(self):
        """Post-processing analysis"""
        self._analyze_privacy_usage()
        self._detect_suspicious_activity()
    
    def _analyze_privacy_usage(self):
        """Analyze Bluetooth privacy feature usage"""
        random_addr_devices = [d for d in self.devices.values() if d.is_random_address]
        
        if len(random_addr_devices) > len(self.devices) * 0.8:  # >80% using random addresses
            event = SecurityEvent(
                event_type='high_privacy_usage',
                severity='INFO',
                description=f'High privacy usage: {len(random_addr_devices)} devices using random addresses',
                source='privacy_analysis',
                timestamp=datetime.now().isoformat(),
                evidence={'random_address_count': len(random_addr_devices)}
            )
            self.security_events.append(event)
    
    def _detect_suspicious_activity(self):
        """Detect suspicious Bluetooth activity"""
        # Check for devices with excessive activity
        high_activity_devices = [
            d for d in self.devices.values() 
            if len(d.rssi_readings) > 1000  # Threshold for suspicious activity
        ]
        
        for device in high_activity_devices:
            event = SecurityEvent(
                event_type='suspicious_bluetooth_activity',
                severity='MEDIUM',
                description=f'High activity device: {device.address} ({len(device.rssi_readings)} packets)',
                source=device.address,
                timestamp=datetime.now().isoformat(),
                evidence={'packet_count': len(device.rssi_readings)}
            )
            self.security_events.append(event)

    def _post_process_analysis(self):
        """Post-processing analysis"""
        # Quick verification of extracted data (temporary)
        print(f"\n🔍 POST-PROCESS VERIFICATION:")
        print(f"Total devices processed: {len(self.devices)}")
    
        devices_with_manufacturer = sum(1 for d in self.devices.values() if d.manufacturer)
        devices_with_names = sum(1 for d in self.devices.values() if d.name)
        devices_with_power = sum(1 for d in self.devices.values() if d.power_level)
    
        print(f"Devices with manufacturer: {devices_with_manufacturer}")
        print(f"Devices with names: {devices_with_names}")
        print(f"Devices with power level: {devices_with_power}")
    
        # Show a sample device with extracted data
        for addr, device in list(self.devices.items())[:3]:
                if device.manufacturer or device.name:
                    print(f"Sample device {addr}: manufacturer='{device.manufacturer}', name='{device.name}', power={device.power_level}")
    
        # Continue with existing post-processing
        self._analyze_privacy_usage()
        self._detect_suspicious_activity()

    def _calculate_rssi_statistics(self, rssi_readings):
        """
        Calculate comprehensive RSSI statistics from readings array
        Replaces large arrays with computed statistics
        """
        if not rssi_readings:
            return {
                'count': 0,
                'avg': None,
                'max': None,
                'min': None,
                'median': None,
                'std_dev': None,
                'range': None,
                'trend': 'unknown',
                'signal_quality': 'unknown'
            }
    
        try:
            import statistics
        
            count = len(rssi_readings)
            avg_rssi = statistics.mean(rssi_readings)
            max_rssi = max(rssi_readings)
            min_rssi = min(rssi_readings)
            median_rssi = statistics.median(rssi_readings)
        
            # Calculate standard deviation if enough samples
            std_dev = statistics.stdev(rssi_readings) if count > 1 else 0
        
            # Calculate range
            signal_range = max_rssi - min_rssi
        
            # Trend analysis (simple slope of first and last values)
            trend = "stable"
            if count > 10:  # Only analyze trend with sufficient data
                first_quarter = statistics.mean(rssi_readings[:count//4]) if count >= 4 else rssi_readings[0]
                last_quarter = statistics.mean(rssi_readings[-count//4:]) if count >= 4 else rssi_readings[-1]
                diff = last_quarter - first_quarter
                if diff > 3:
                    trend = "improving"  # Signal getting stronger
                elif diff < -3:
                    trend = "degrading"  # Signal getting weaker
        
            # Signal quality assessment
            signal_quality = "unknown"
            if avg_rssi > -30:
                signal_quality = "excellent"
            elif avg_rssi > -50:
                signal_quality = "very_good"
            elif avg_rssi > -60:
                signal_quality = "good"
            elif avg_rssi > -70:
                signal_quality = "fair"
            elif avg_rssi > -80:
                signal_quality = "poor"
            else:
                signal_quality = "very_poor"
        
            return {
                'count': count,
                'avg': round(avg_rssi, 2),
                'max': max_rssi,
                'min': min_rssi,
                'median': round(median_rssi, 2),
                'std_dev': round(std_dev, 2),
                'range': signal_range,
                'trend': trend,
                'signal_quality': signal_quality,
            }
        
        except Exception as e:
            return {
                'count': len(rssi_readings),
                'error': str(e),
                'avg': sum(rssi_readings) / len(rssi_readings) if rssi_readings else 0,
                'max': max(rssi_readings) if rssi_readings else None,
                'min': min(rssi_readings) if rssi_readings else None
            }

    def _compress_device_data(self, devices):
        """
        Compress Bluetooth device data by removing unnecessary fields and optimizing data structures
        This is called just before returning AnalysisResult
        """
        compressed_devices = {}
    
        for address, device in devices.items():
            compressed_device = {}
        
            # Essential Bluetooth device information (always keep)
            essential_fields = [
                'address', 'first_seen', 'last_seen', 'name', 'address_type', 
                'device_type', 'manufacturer', 'is_random_address', 'power_level',
                'company_id', 'privacy_enabled'
            ]
        
            for field in essential_fields:
                if hasattr(device, field):
                    compressed_device[field] = getattr(device, field)
        
            # Services (convert to list)
            if hasattr(device, 'services') and device.services:
                compressed_device['services'] = list(device.services)
        
            # RSSI Data Compression (same as WiFi)
            rssi_readings = getattr(device, 'rssi_readings', [])
            if rssi_readings and max(rssi_readings) <= -85:
                continue
        
            if rssi_readings:
                compressed_device['rssi_statistics'] = self._calculate_rssi_statistics(rssi_readings)
                compressed_device['rssi_samples'] = {
                    'first_5': rssi_readings[:2],
                    'last_5': rssi_readings[-2:],
                    'total_count': len(rssi_readings)
                }
            else:
                compressed_device['rssi_statistics'] = {
                    'count': 0, 'avg': None, 'max': None, 'min': None, 'samples': []
                }
        
            # Remove debug fields temporarily
            debug_fields = ['extraction_debug_info', 'raw_advertising_data']
            for field in debug_fields:
                if hasattr(device, field):
                    setattr(device, field, None)
        
            compressed_devices[address] = compressed_device
    
        return compressed_devices

# =============================================================================
# ADAPTER FACTORY
# =============================================================================

class AdapterFactory:
    """Factory for creating appropriate adapters"""
    
    def __init__(self):
        self.adapters = [
            ESP32WiFiAdapter,
            nRFBluetoothAdapter,
            NetworkTrafficAdapter
        ]
    
    def get_adapter(self, file_path: str, config: Dict = None) -> Optional[CaptureAdapter]:
        """Get appropriate adapter for file with proper prioritization"""
        filename = Path(file_path).name.lower()
        
        # Special handling for honeypot files - prioritize NetworkTrafficAdapter
        if 'honeypot' in filename or 'vlan' in filename:
            network_adapter = NetworkTrafficAdapter(config)
            if network_adapter.can_handle(file_path):
                logger.info(f"Selected NetworkTrafficAdapter for {file_path}")
                return network_adapter
        
        # Regular adapter selection for other files
        for adapter_class in self.adapters:
            adapter = adapter_class(config)
            if adapter.can_handle(file_path):
                logger.info(f"Selected {adapter_class.__name__} for {file_path}")
                return adapter
        
        logger.warning(f"No suitable adapter found for {file_path}")
        return None
    
    def get_all_adapters(self, config: Dict = None) -> List[CaptureAdapter]:
        """Get all available adapters"""
        return [adapter_class(config) for adapter_class in self.adapters]
    
# ADD THIS TO YOUR adapter_interfaces.py file

class NetworkTrafficAdapter(CaptureAdapter):
    """Adapter for Network Traffic PCAP analysis (Honeypot VLAN monitoring)"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.connections = {}  # Flow tracking
        self.flow_summary = NetworkFlowSummary()
        self.honeypot_subnets = self.config.get('honeypot_subnets', [
            '192.168.66.',  # VLAN 66 subnet
            '10.0.66.',     # Alternative subnet
        ])
        self.suspicious_ports = self.config.get('suspicious_ports', [
            22, 23, 21, 25, 53, 80, 443, 3389, 5900, 1433, 3306
        ])
    
    def can_handle(self, file_path: str) -> bool:
        """Check if file is a network traffic capture"""
        filename = Path(file_path).name.lower()
        network_patterns = ['honeypot', 'vlan', 'network', 'traffic', 'pcap']
        return any(pattern in filename for pattern in network_patterns)
    
    def get_device_type(self) -> type:
        """Return network connection data type"""
        return NetworkConnectionData
    
    def parse_file(self, file_path: str) -> AnalysisResult:
        """Parse Network Traffic PCAP file"""
        logger.info(f"Network Adapter: Parsing {file_path}")
        self.reset_statistics()
        
        try:
            # Configure PyShark for network traffic
            capture = pyshark.FileCapture(
                file_path,
                include_raw=True,
                use_json=True
                # No display filter - capture all network traffic
            )
            
            for packet in capture:
                self._process_network_packet(packet)
                self.processed_packets += 1
                
                if self.processed_packets % 5000 == 0:
                    logger.info(f"Network: Processed {self.processed_packets} packets")
            
            capture.close()
            self._post_process_network_analysis()
            
            return AnalysisResult(
                protocol='NetworkTraffic',
                capture_source='RaspberryPi_VLAN66',
                devices={conn_id: asdict(conn) for conn_id, conn in self.connections.items()},
                security_events=self.security_events,
                statistics=self._get_network_statistics(),
                metadata={'file_path': file_path, 'adapter': 'NetworkTrafficAdapter'}
            )
            
        except Exception as e:
            logger.error(f"Network Adapter error: {e}")
            return AnalysisResult(
                protocol='NetworkTraffic',
                capture_source='RaspberryPi_VLAN66',
                devices={},
                security_events=[],
                statistics={'error': str(e)},
                metadata={'file_path': file_path, 'error': True}
            )
    
    def _process_network_packet(self, packet):
        """Process individual network packet"""
        try:
            timestamp = str(packet.sniff_time)
            
            # Extract network layer information
            src_ip = dst_ip = None
            src_port = dst_port = None
            protocol = packet.highest_layer
            packet_size = int(packet.length) if hasattr(packet, 'length') else 0
            
            # Extract IP information
            if hasattr(packet, 'ip'):
                src_ip = getattr(packet.ip, 'src', None)
                dst_ip = getattr(packet.ip, 'dst', None)
                protocol = getattr(packet.ip, 'proto', protocol)
            
            # Extract transport layer information
            if hasattr(packet, 'tcp'):
                src_port = int(getattr(packet.tcp, 'srcport', 0))
                dst_port = int(getattr(packet.tcp, 'dstport', 0))
                connection_state = getattr(packet.tcp, 'flags', None)
            elif hasattr(packet, 'udp'):
                src_port = int(getattr(packet.udp, 'srcport', 0))
                dst_port = int(getattr(packet.udp, 'dstport', 0))
                connection_state = 'UDP'
            else:
                connection_state = 'OTHER'
            
            # Create connection identifier
            if src_ip and dst_ip:
                connection_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                
                # Initialize or update connection
                if connection_id not in self.connections:
                    self.connections[connection_id] = NetworkConnectionData(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        first_seen=timestamp,
                        connection_state=connection_state,
                        is_honeypot_target=self._is_honeypot_target(dst_ip)
                    )
                
                # Update connection data
                conn = self.connections[connection_id]
                conn.packet_count += 1
                conn.bytes_transferred += packet_size
                conn.last_seen = timestamp
                
                # Track protocols used
                if protocol not in conn.protocols_used:
                    conn.protocols_used.append(protocol)
                
                # Analyze for suspicious patterns
                self._analyze_packet_for_threats(packet, conn, timestamp)
                
                # Update flow summary
                self._update_flow_summary(src_ip, dst_ip, dst_port, packet_size, protocol)
        
        except Exception as e:
            logger.debug(f"Network: Error processing packet: {e}")
    
    def _is_honeypot_target(self, ip: str) -> bool:
        """Check if IP is in honeypot subnet"""
        return any(ip.startswith(subnet) for subnet in self.honeypot_subnets)
    
    def _analyze_packet_for_threats(self, packet, connection: NetworkConnectionData, timestamp: str):
        """Analyze packet for security threats"""
        
        # 1. Honeypot connection detection
        if connection.is_honeypot_target:
            event = SecurityEvent(
                event_type='honeypot_connection',
                severity='HIGH',
                description=f'Connection to honeypot: {connection.src_ip} -> {connection.dst_ip}:{connection.dst_port}',
                source=connection.src_ip,
                timestamp=timestamp,
                evidence={
                    'destination': connection.dst_ip,
                    'port': connection.dst_port,
                    'protocol': connection.protocol
                }
            )
            self.security_events.append(event)
        
        # 2. Suspicious port scanning
        if connection.dst_port in self.suspicious_ports:
            connection.suspicious_patterns.append(f'suspicious_port_{connection.dst_port}')
        
        # 3. Protocol analysis
        self._analyze_application_protocols(packet, connection, timestamp)
        
        # 4. Data exfiltration detection
        if connection.bytes_transferred > 1024 * 1024:  # > 1MB
            connection.suspicious_patterns.append('large_data_transfer')
    
    def _analyze_application_protocols(self, packet, connection: NetworkConnectionData, timestamp: str):
        """Analyze application layer protocols"""
        
        # HTTP Analysis
        if hasattr(packet, 'http'):
            method = getattr(packet.http, 'request_method', None)
            uri = getattr(packet.http, 'request_uri', None)
            user_agent = getattr(packet.http, 'user_agent', None)
            
            if method and uri:
                event = SecurityEvent(
                    event_type='http_request_to_honeypot',
                    severity='MEDIUM',
                    description=f'HTTP {method} request to honeypot: {uri}',
                    source=connection.src_ip,
                    timestamp=timestamp,
                    evidence={
                        'method': method,
                        'uri': uri,
                        'user_agent': user_agent,
                        'destination': connection.dst_ip
                    }
                )
                self.security_events.append(event)
        
        # DNS Analysis
        elif hasattr(packet, 'dns'):
            query_name = getattr(packet.dns, 'qry_name', None)
            if query_name:
                connection.suspicious_patterns.append(f'dns_query_{query_name}')
        
        # SSH Analysis
        elif hasattr(packet, 'ssh'):
            event = SecurityEvent(
                event_type='ssh_connection_to_honeypot',
                severity='HIGH',
                description=f'SSH connection attempt to honeypot from {connection.src_ip}',
                source=connection.src_ip,
                timestamp=timestamp,
                evidence={'destination': connection.dst_ip, 'port': connection.dst_port}
            )
            self.security_events.append(event)
        
        # FTP Analysis
        elif hasattr(packet, 'ftp'):
            command = getattr(packet.ftp, 'request_command', None)
            if command:
                event = SecurityEvent(
                    event_type='ftp_activity_on_honeypot',
                    severity='MEDIUM',
                    description=f'FTP command on honeypot: {command}',
                    source=connection.src_ip,
                    timestamp=timestamp,
                    evidence={'command': command, 'destination': connection.dst_ip}
                )
                self.security_events.append(event)
    
    def _update_flow_summary(self, src_ip: str, dst_ip: str, dst_port: int, 
                           packet_size: int, protocol: str):
        """Update network flow summary statistics"""
        self.flow_summary.total_bytes += packet_size
        
        # Update protocol breakdown
        if protocol not in self.flow_summary.protocol_breakdown:
            self.flow_summary.protocol_breakdown[protocol] = 0
        self.flow_summary.protocol_breakdown[protocol] += 1
        
        # Track honeypot connections
        if self._is_honeypot_target(dst_ip):
            self.flow_summary.honeypot_connections += 1
    
    def _post_process_network_analysis(self):
        """Post-processing network analysis"""
        # Update flow summary with final counts
        unique_src_ips = set()
        unique_dst_ips = set()
        
        for conn in self.connections.values():
            unique_src_ips.add(conn.src_ip)
            unique_dst_ips.add(conn.dst_ip)
            
            # Calculate connection duration
            if conn.first_seen and conn.last_seen:
                try:
                    first = datetime.fromisoformat(conn.first_seen.replace('Z', '+00:00'))
                    last = datetime.fromisoformat(conn.last_seen.replace('Z', '+00:00'))
                    conn.connection_duration = (last - first).total_seconds()
                except:
                    pass
        
        self.flow_summary.total_connections = len(self.connections)
        self.flow_summary.unique_source_ips = len(unique_src_ips)
        self.flow_summary.unique_destination_ips = len(unique_dst_ips)
        
        # Identify top talkers
        top_talkers = sorted(
            self.connections.values(),
            key=lambda x: x.bytes_transferred,
            reverse=True
        )[:10]
        
        self.flow_summary.top_talkers = [
            {
                'connection': f"{conn.src_ip}->{conn.dst_ip}:{conn.dst_port}",
                'bytes': conn.bytes_transferred,
                'packets': conn.packet_count,
                'protocol': conn.protocol
            }
            for conn in top_talkers
        ]
        
        # Advanced threat analysis
        self._detect_advanced_network_threats()
    
    def _detect_advanced_network_threats(self):
        """Detect advanced network-level threats"""
        
        # Port scanning detection
        src_connections = defaultdict(list)
        for conn in self.connections.values():
            src_connections[conn.src_ip].append(conn)
        
        for src_ip, connections in src_connections.items():
            unique_ports = set(conn.dst_port for conn in connections if conn.dst_port)
            
            # Potential port scan (>10 different ports from same source)
            if len(unique_ports) > 10:
                event = SecurityEvent(
                    event_type='potential_port_scan',
                    severity='HIGH',
                    description=f'Potential port scan: {src_ip} connected to {len(unique_ports)} different ports',
                    source=src_ip,
                    timestamp=datetime.now().isoformat(),
                    evidence={
                        'unique_ports': list(unique_ports),
                        'connection_count': len(connections)
                    }
                )
                self.security_events.append(event)
        
        # Data exfiltration detection
        large_transfers = [conn for conn in self.connections.values() 
                          if conn.bytes_transferred > 10 * 1024 * 1024]  # >10MB
        
        for conn in large_transfers:
            event = SecurityEvent(
                event_type='large_data_transfer',
                severity='MEDIUM',
                description=f'Large data transfer detected: {conn.bytes_transferred} bytes from {conn.src_ip}',
                source=conn.src_ip,
                timestamp=conn.last_seen,
                evidence={
                    'bytes': conn.bytes_transferred,
                    'destination': conn.dst_ip,
                    'duration': conn.connection_duration
                }
            )
            self.security_events.append(event)
        
        # Suspicious protocol analysis
        self._analyze_protocol_anomalies()
    
    def _analyze_protocol_anomalies(self):
        """Analyze for protocol-specific anomalies"""
        
        # Look for connections using multiple protocols (potential tunneling)
        multi_protocol_connections = [
            conn for conn in self.connections.values() 
            if len(conn.protocols_used) > 2
        ]
        
        for conn in multi_protocol_connections:
            event = SecurityEvent(
                event_type='multi_protocol_connection',
                severity='MEDIUM',
                description=f'Connection using multiple protocols: {", ".join(conn.protocols_used)}',
                source=conn.src_ip,
                timestamp=conn.last_seen,
                evidence={
                    'protocols': conn.protocols_used,
                    'destination': conn.dst_ip,
                    'port': conn.dst_port
                }
            )
            self.security_events.append(event)
    
    def _get_network_statistics(self) -> Dict[str, Any]:
        """Get comprehensive network statistics"""
        base_stats = self.get_statistics()
        
        network_stats = {
            'flow_summary': asdict(self.flow_summary),
            'connection_analysis': {
                'total_unique_connections': len(self.connections),
                'avg_connection_duration': self._calculate_avg_duration(),
                'avg_bytes_per_connection': self._calculate_avg_bytes(),
                'most_active_source_ip': self._get_most_active_source(),
                'most_targeted_destination': self._get_most_targeted_destination()
            },
            'threat_analysis': {
                'honeypot_activity_detected': self.flow_summary.honeypot_connections > 0,
                'suspicious_patterns_found': sum(len(conn.suspicious_patterns) for conn in self.connections.values()),
                'high_risk_connections': len([conn for conn in self.connections.values() 
                                            if conn.is_honeypot_target or len(conn.suspicious_patterns) > 0])
            }
        }
        
        return {**base_stats, **network_stats}
    
    def _calculate_avg_duration(self) -> float:
        """Calculate average connection duration"""
        durations = [conn.connection_duration for conn in self.connections.values() 
                    if conn.connection_duration is not None]
        return sum(durations) / len(durations) if durations else 0.0
    
    def _calculate_avg_bytes(self) -> float:
        """Calculate average bytes per connection"""
        if not self.connections:
            return 0.0
        return sum(conn.bytes_transferred for conn in self.connections.values()) / len(self.connections)
    
    def _get_most_active_source(self) -> Optional[str]:
        """Get most active source IP"""
        src_activity = defaultdict(int)
        for conn in self.connections.values():
            src_activity[conn.src_ip] += conn.packet_count
        
        if src_activity:
            return max(src_activity, key=src_activity.get)
        return None
    
    def _get_most_targeted_destination(self) -> Optional[str]:
        """Get most targeted destination"""
        dst_activity = defaultdict(int)
        for conn in self.connections.values():
            dst_activity[conn.dst_ip] += conn.packet_count
        
        if dst_activity:
            return max(dst_activity, key=dst_activity.get)
        return None

# Real-time alerting functions (commented out as requested)
    
    # def _send_real_time_alert(self, event: SecurityEvent):
    #     """Send real-time alert for critical events"""
    #     if event.severity == 'HIGH':
    #         # Email alert
    #         # self._send_email_alert(event)
    #         
    #         # Slack notification
    #         # self._send_slack_alert(event)
    #         
    #         # Windows notification
    #         # self._send_windows_notification(event)
    #         pass
    
    # def _send_email_alert(self, event: SecurityEvent):
    #     """Send email alert"""
    #     # import smtplib
    #     # from email.mime.text import MIMEText
    #     # Implementation for email alerts
    #     pass
    
    # def _send_slack_alert(self, event: SecurityEvent):
    #     """Send Slack notification"""
    #     # import requests
    #     # Implementation for Slack webhooks
    #     pass
    
    # def _send_windows_notification(self, event: SecurityEvent):
    #     """Send Windows toast notification"""
    #     # from plyer import notification
    #     # Implementation for Windows notifications
    #     pass
    
    # Rest of the factory stays the same...

# UPDATE YOUR create_default_config() in main_wireshark_execution.py

def create_default_config():
    return {
        'honeypot_networks': ['Admin_Network_Test', 'casa_IoT', 'mis_invitadas'],
        'honeypot_subnets': ['192.168.66.', '10.0.66.'],  # Add this
        'suspicious_ports': [22, 23, 21, 25, 53, 80, 443, 3389, 5900, 1433, 3306],  # Add this
        'security_thresholds': {
            'deauth_attack_threshold': 20,
            'deauth_time_window': 60,
            'large_transfer_threshold_mb': 10,
            'port_scan_threshold': 10
        },
        'output_settings': {
            'save_individual_results': False,
            'compress_large_files': True,
            'update_consolidated_report': True
        }
    }