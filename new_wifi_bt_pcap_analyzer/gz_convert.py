#!/usr/bin/env python3
"""
Honeypot TAR.GZ to PCAP Converter
Extracts .pcap files from tar.gz archives and places them in WiFI_BT pcaps folder
"""

import gzip
import tarfile
import os
import glob
from pathlib import Path
import shutil

# Hardcoded paths
DOWNLOADS_PATH = r"C:\Users\Gavin\Downloads"
OUTPUT_PATH = r"C:\Users\Gavin\Desktop\WiFI_BT pcaps"

def find_gz_files() -> list:
    """Find all .gz files in the downloads directory"""
    gz_files = []
    gz_files.extend(glob.glob(os.path.join(DOWNLOADS_PATH, "*.gz")))
    gz_files.extend(glob.glob(os.path.join(DOWNLOADS_PATH, "*.tar.gz")))
    return gz_files

def get_next_filename() -> str:
    """Generate next available honeypotUNi#.pcap filename"""
    counter = 1
    while True:
        filename = f"honeypotUNi{counter}.pcap"
        full_path = os.path.join(OUTPUT_PATH, filename)
        if not os.path.exists(full_path):
            return filename
        counter += 1

def extract_pcap_from_targz(input_file: str, output_filename: str) -> bool:
    """
    Extract PCAP file from tar.gz archive
    
    Args:
        input_file: Path to the .tar.gz file
        output_filename: Just the filename (not full path)
    
    Returns:
        bool: True if successful, False otherwise
    """
    
    output_path = os.path.join(OUTPUT_PATH, output_filename)
    
    print(f"🔄 Extracting: {os.path.basename(input_file)} -> {output_filename}")
    
    try:
        # Create output directory if it doesn't exist
        os.makedirs(OUTPUT_PATH, exist_ok=True)
        
        # Open the tar.gz file
        with gzip.open(input_file, 'rb') as gz_file:
            with tarfile.open(fileobj=gz_file, mode='r') as tar:
                
                # List all files in the archive
                file_list = tar.getnames()
                print(f"📋 Files in archive: {file_list}")
                
                # Find PCAP files in the archive
                pcap_files = [f for f in file_list if f.endswith('.pcap') or f.endswith('.pcapng')]
                
                if not pcap_files:
                    print(f"❌ No PCAP files found in archive")
                    return False
                
                # Extract the first PCAP file found
                pcap_file = pcap_files[0]
                print(f"📦 Extracting PCAP file: {pcap_file}")
                
                # Extract the file
                extracted_file = tar.extractfile(pcap_file)
                if extracted_file is None:
                    print(f"❌ Could not extract {pcap_file}")
                    return False
                
                # Read the PCAP data
                pcap_data = extracted_file.read()
                print(f"📊 Extracted {len(pcap_data)} bytes")
                
                # Write to output file
                with open(output_path, 'wb') as output_file:
                    output_file.write(pcap_data)
                
                print(f"✅ Successfully created: {output_path}")
                print(f"📁 Output file size: {os.path.getsize(output_path)} bytes")
                
                # Show info about other PCAP files if there are more
                if len(pcap_files) > 1:
                    print(f"ℹ️  Note: Found {len(pcap_files)} PCAP files, extracted first one:")
                    for i, pf in enumerate(pcap_files):
                        marker = "✅" if i == 0 else "⏭️"
                        print(f"   {marker} {pf}")
                
                return True
        
    except gzip.BadGzipFile:
        print(f"❌ Error: '{input_file}' is not a valid gzip file")
        return False
    except tarfile.TarError as e:
        print(f"❌ Error: Could not read tar archive - {e}")
        return False
    except Exception as e:
        print(f"❌ Error during extraction: {e}")
        return False

def validate_pcap_header(file_path: str) -> bool:
    """Check if the extracted file has a valid PCAP header"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
        
        # PCAP magic numbers
        pcap_magic_le = b'\xd4\xc3\xb2\xa1'  # Little endian
        pcap_magic_be = b'\xa1\xb2\xc3\xd4'  # Big endian
        pcapng_magic = b'\x0a\x0d\x0d\x0a'   # PCAP-NG
        
        if header == pcap_magic_le:
            print("🔍 Valid PCAP file detected (little endian)")
            return True
        elif header == pcap_magic_be:
            print("🔍 Valid PCAP file detected (big endian)")
            return True
        elif header == pcapng_magic:
            print("🔍 Valid PCAP-NG file detected")
            return True
        else:
            print(f"⚠️  Warning: Unusual header format")
            print(f"   Header bytes: {header.hex()}")
            print(f"   File might still be valid, trying analysis anyway...")
            return False
            
    except Exception as e:
        print(f"❌ Error validating file: {e}")
        return False

def preview_archive_contents(gz_file: str) -> None:
    """Show contents of tar.gz archive before extraction"""
    try:
        print(f"🔍 Previewing contents of {os.path.basename(gz_file)}:")
        
        with gzip.open(gz_file, 'rb') as gz:
            with tarfile.open(fileobj=gz, mode='r') as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        size_mb = member.size / (1024 * 1024)
                        file_type = "📦 PCAP" if member.name.endswith(('.pcap', '.pcapng')) else "📄 Other"
                        print(f"   {file_type} {member.name} ({size_mb:.2f} MB)")
                    elif member.isdir():
                        print(f"   📁 Directory: {member.name}")
        print()
        
    except Exception as e:
        print(f"   ❌ Could not preview archive: {e}")

def main():
    """Main extraction function"""
    print("📦 Honeypot TAR.GZ to PCAP Converter")
    print("=" * 50)
    print(f"📁 Looking for .gz files in: {DOWNLOADS_PATH}")
    print(f"📁 Output directory: {OUTPUT_PATH}")
    print()
    
    # Find all .gz files
    gz_files = find_gz_files()
    
    if not gz_files:
        print("❌ No .gz files found in Downloads folder")
        return
    
    print(f"📋 Found {len(gz_files)} .gz file(s):")
    for i, gz_file in enumerate(gz_files, 1):
        print(f"   {i}. {os.path.basename(gz_file)}")
    print()
    
    # Process each .gz file
    successful_conversions = []
    
    for gz_file in gz_files:
        print("-" * 50)
        
        # Preview archive contents
        preview_archive_contents(gz_file)
        
        # Generate next filename
        output_filename = get_next_filename()
        
        # Extract PCAP from archive
        success = extract_pcap_from_targz(gz_file, output_filename)
        
        if success:
            output_path = os.path.join(OUTPUT_PATH, output_filename)
            
            # Validate the extracted file
            print("🔍 Validating extracted PCAP file...")
            is_valid = validate_pcap_header(output_path)
            
            if is_valid:
                successful_conversions.append(output_filename)
                print(f"🎉 {output_filename} ready for triangulation analysis!")
            else:
                successful_conversions.append(output_filename)
                print(f"⚠️  {output_filename} extracted - may work even with unusual header")
        
        print()
    
    # Summary
    print("=" * 50)
    if successful_conversions:
        print(f"✅ Successfully extracted {len(successful_conversions)} PCAP file(s):")
        for filename in successful_conversions:
            full_path = os.path.join(OUTPUT_PATH, filename)
            size_mb = os.path.getsize(full_path) / (1024 * 1024)
            print(f"   📁 {filename} ({size_mb:.2f} MB)")
        print(f"\n🎯 Files are ready for your wireless forensics analyzer!")
        print(f"🔍 Place in triangulation: rssi1.pcap, rssi2.pcap, rssi3.pcap")
    else:
        print("❌ No files were successfully extracted")

if __name__ == "__main__":
    main()