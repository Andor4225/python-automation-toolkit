import secrets
import string
import random

def create_strong_password(length: int) -> str:
    """Generates a cryptographically strong password with guaranteed complexity."""
    
    # Define the character sets to use for the password
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation  # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~

    # Combine all character sets into a single pool for random selection
    full_character_pool = lowercase + uppercase + digits + symbols

    # Start the password with at least one character from each required set
    # This guarantees the password meets complexity requirements
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    # Fill the rest of the password length with random characters from the full pool
    remaining_length = length - len(password_chars)
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(full_character_pool))

    # Shuffle the list of characters to ensure the starting characters aren't predictable
    random.shuffle(password_chars)
    
    # Join the characters together to form the final password string
    return "".join(password_chars)

if __name__ == "__main__":
    while True:
        try:
            # Prompt the user for the desired password length
            password_length_str = input("Enter the desired password length (minimum 12 recommended): ")
            password_length = int(password_length_str)
            
            # Ensure the password length is reasonably secure
            if password_length < 12:
                print("Warning: A password length of less than 12 is not recommended.")
                confirm = input("Are you sure you want to continue? (y/n): ").lower()
                if confirm != 'y':
                    continue
            
            if password_length < 4:
                print("Error: Password length must be at least 4 to include all character types.")
                continue

            # Generate and print the password
            new_password = create_strong_password(password_length)
            print("\n" + "="*25)
            print(f"Generated Password: {new_password}")
            print("="*25 + "\n")
            break

        except ValueError:
            print("Invalid input. Please enter a number for the length.")