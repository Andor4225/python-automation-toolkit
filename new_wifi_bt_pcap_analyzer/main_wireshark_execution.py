import logging
from pathlib import Path
from main_analyzer_orchestrator import WirelessForensicsAnalyzer
from main_analyzer_orchestrator import TriangulationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wireless_analyzer.log'),
        logging.StreamHandler()
    ]
)

# Define default configuration
def create_default_config():
    return {
        'watch_directory': r"C:\Users\Gavin\Desktop\WiFI_BT pcaps",
        'output_directory': r"C:\Users\Gavin\Desktop\WiFi & BT Analysis"
    }

# Then just call main() from main_analyzer_orchestrator
def main():
    config = create_default_config()
    analyzer = WirelessForensicsAnalyzer(
        watch_directory=config['watch_directory'],
        output_directory=config['output_directory'],
        config=config
    )
    analyzer.process_existing_files()
    analyzer.start_monitoring()

if __name__ == "__main__":
    main()