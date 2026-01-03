# qr_generator.py

A simple utility for encoding passwords (or any sensitive text) into QR codes for secure offline storage or transfer.

## Overview

qr_generator creates a PNG image containing a QR code representation of your password. Input is hidden during entry using `getpass`, and the resulting image can be printed or stored for use with password managers, device provisioning, or secure sharing.

## Features

- **Hidden input** using `getpass` to prevent shoulder surfing
- **Standard QR format** compatible with any QR scanner
- **Clean PNG output** with configurable styling
- **Error correction** built into the QR specification

## Requirements

- Python 3.6+
- `qrcode` library
- `Pillow` (PIL) for image generation

## Installation

```bash
git clone https://github.com/yourusername/qr_generator.git
cd qr_generator
pip install qrcode[pil]
```

Or install dependencies manually:

```bash
pip install qrcode Pillow
```

## Usage

Run the script:

```bash
python qr_generator.py
```

You'll be prompted to enter a password (input is hidden):

```
Enter the password to encode: 
Success! QR code saved as 'password_qr.png'
⚠️  Remember: This QR code contains your unencrypted password. Keep it secure.
```

The QR code is saved as `password_qr.png` in the current directory.

### As a Module

```python
from qr_generator import create_password_qr

create_password_qr()
```

## QR Code Specifications

| Parameter        | Value                          |
|------------------|--------------------------------|
| Version          | 1 (auto-fit enabled)           |
| Error Correction | Level L (7% recovery)          |
| Box Size         | 10 pixels                      |
| Border           | 4 modules (standard minimum)   |
| Colors           | Black on white                 |

## Security Considerations

**Important:** The generated QR code contains your password in plaintext. Anyone who scans the code will have access to it.

Recommended practices:
- Store the QR image in an encrypted volume or secure location
- Delete the image after use if it was created for one-time transfer
- Do not upload the QR image to cloud storage or send via unencrypted channels
- Consider this tool for air-gapped transfers or physical backup scenarios

## Use Cases

- Transferring complex passwords to mobile devices without typing
- Creating physical backups of master passwords for secure storage
- Provisioning devices in environments where manual entry is impractical
- Sharing credentials in person without digital transmission

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.
