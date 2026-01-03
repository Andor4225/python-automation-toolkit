# Password Checker

import msvcrt


def password_checker(password):
    score = 0

    if strength != "Strong":
        print("Improve password")
        return False

    else:
        print("Password is good!")
        return True


def new_func(password):
    score = sum([
        len(password) >= 12,
        any(c.isdigit() for c in password),
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/" for c in password)
    ])

    if score >= 0 and score <= 2:
        return "Weak"
    elif score > 2 and score <= 4:
        return "Moderate"
    else:
        return "Strong"


def get_password_with_asterisks(prompt="Password: "):
    print(prompt, end='', flush=True)
    password = ""
    while True:
        ch = msvcrt.getch()
        if ch in {b'\r', b'\n'}:  # Enter key pressed
            print('')
            break
        elif ch == b'\x08':  # Backspace pressed
            if len(password) > 0:
                password = password[:-1]
                print('\b \b', end='', flush=True)
        elif ch == b'\x03':  # Ctrl+C
            raise KeyboardInterrupt
        else:
            password += ch.decode('utf-8', errors='ignore')
            print('*', end='', flush=True)
    return password


while True:
    print("Welcome to the Password Checker!")
    user_choice = input(
        "Would you like to check a password? (yes/y) or (exit): ").strip().lower()
    if user_choice == 'exit':
        print("Exiting the password checker.")
        break
    if user_choice in ('yes', 'y'):
        password = get_password_with_asterisks("Please enter your password: ")
        strength = new_func(password)
        print(f"Your password is: {strength}")
        password_checker(password)
    continue