import os
import time
import queue
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# =============================================================================
# FILE WATCHER
# =============================================================================

# Configure logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class PcapFileHandler(FileSystemEventHandler):
    """Handles new PCAP file events"""
    
    def __init__(self, processor_queue: queue.Queue):
        self.processor_queue = processor_queue
        self.processed_files = set()
    
    def on_created(self, event):
        """Handle new file creation"""
        if not event.is_directory and event.src_path.endswith('.pcap'):
            # Wait a moment for file to be fully written
            time.sleep(2)
            
            if event.src_path not in self.processed_files:
                logger.info(f"New PCAP detected: {event.src_path}")
                self.processor_queue.put(event.src_path)
                self.processed_files.add(event.src_path)
    
    def on_modified(self, event):
        """Handle file modification (in case of streaming captures)"""
        if not event.is_directory and event.src_path.endswith('.pcap'):
            if event.src_path not in self.processed_files:
                time.sleep(2)  # Wait for write completion
                logger.info(f"Modified PCAP detected: {event.src_path}")
                self.processor_queue.put(event.src_path)
                self.processed_files.add(event.src_path)