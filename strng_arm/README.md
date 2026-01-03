# strng_arm.py

A cryptographically secure password generator built with Python's `secrets` module.

## Overview

strng_arm generates strong, randomized passwords that meet modern complexity requirements. It guarantees each password contains at least one lowercase letter, one uppercase letter, one digit, and one special character—making it suitable for systems with strict password policies.

## Features

- **Cryptographically secure randomness** using Python's `secrets` module
- **Guaranteed complexity** with enforced character type requirements
- **Configurable length** with safety warnings for short passwords
- **Interactive CLI** with input validation

## Requirements

- Python 3.6+

No external dependencies required—uses only Python standard library modules.

## Installation

```bash
git clone https://github.com/yourusername/strng_arm.git
cd strng_arm
```

## Usage

Run the script directly:

```bash
python strng_arm.py
```

You'll be prompted to enter your desired password length:

```
Enter the desired password length (minimum 12 recommended): 16

=========================
Generated Password: k9#Qm2!xLpR@4nYv
=========================
```

### As a Module

You can also import the function into your own projects:

```python
from strng_arm import create_strong_password

password = create_strong_password(20)
print(password)
```

## Security Notes

- **Minimum length of 12 characters** is recommended for adequate entropy
- **Minimum length of 4 characters** is enforced to satisfy all character type requirements
- The generator uses `secrets.choice()` which is suitable for cryptographic purposes, unlike `random.choice()`
- Passwords are shuffled after generation to prevent predictable character positioning

## Character Sets

The generator draws from the following character pools:

| Type       | Characters                                      |
|------------|------------------------------------------------|
| Lowercase  | `a-z`                                          |
| Uppercase  | `A-Z`                                          |
| Digits     | `0-9`                                          |
| Symbols    | `!"#$%&'()*+,-./:;<=>?@[\]^_`{\|}~`            |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.
