import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from collections import defaultdict
from pathlib import Path
import pyshark

# Configure logger
logger = logging.getLogger(__name__)

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class DeviceData:
    """Base device data structure"""
    address: str
    rssi_readings: List[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    
    def __post_init__(self):
        if self.rssi_readings is None:
            self.rssi_readings = []

@dataclass
class WiFiDeviceData(DeviceData):
    """WiFi-specific device data"""
    ssid: Optional[str] = None
    channels: List[int] = None
    encryption: Optional[str] = None
    frame_types: List[str] = None
    is_hidden: bool = False
    deauth_count: int = 0
    beacon_interval: Optional[int] = None
    
    def __post_init__(self):
        super().__post_init__()
        if self.channels is None:
            self.channels = []
        if self.frame_types is None:
            self.frame_types = []

@dataclass
class BluetoothDeviceData(DeviceData):
    """Bluetooth-specific device data"""
    name: Optional[str] = None
    address_type: Optional[str] = None
    device_type: Optional[str] = None
    services: List[str] = None
    manufacturer: Optional[str] = None
    is_random_address: bool = False

    # NEW FIELDS - Add these:
    power_level: Optional[int] = None
    company_id: Optional[str] = None
    privacy_enabled: bool = False
    extraction_debug_info: Optional[Dict] = None
    raw_advertising_data: Optional[str] = None
    
    def __post_init__(self):
        super().__post_init__()
        if self.services is None:
            self.services = []

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    severity: str
    description: str
    source: str
    timestamp: str
    evidence: Dict = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {}
        self.event_id = hashlib.md5(f"{self.event_type}{self.source}{self.timestamp}".encode()).hexdigest()[:8]

@dataclass
class AnalysisResult:
    """Standardized analysis result"""
    protocol: str
    capture_source: str
    devices: Dict[str, Any]
    security_events: List[SecurityEvent]
    statistics: Dict[str, Any]
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class NetworkConnectionData:
    """Network connection/flow data"""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    packet_count: int = 0
    bytes_transferred: int = 0
    connection_duration: Optional[float] = None
    connection_state: Optional[str] = None
    protocols_used: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    geolocation: Optional[str] = None
    is_honeypot_target: bool = False

@dataclass
class NetworkFlowSummary:
    """Summary of network flow analysis"""
    total_connections: int = 0
    unique_source_ips: int = 0
    unique_destination_ips: int = 0
    total_bytes: int = 0
    protocol_breakdown: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Dict] = field(default_factory=list)
    honeypot_connections: int = 0
    suspicious_activity_count: int = 0