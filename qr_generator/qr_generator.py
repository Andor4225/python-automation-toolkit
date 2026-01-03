import qrcode
import getpass

def create_password_qr():
    """
    Prompts the user for a password and generates a QR code from it.
    """
    try:
        # Use getpass to hide the password as you type
        password = getpass.getpass("Enter the password to encode: ")

        if not password:
            print("Password cannot be empty. Aborting.")
            return

        # Create a QR code object
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )

        # Add the password data to the QR code
        qr.add_data(password)
        qr.make(fit=True)

        # Create an image from the QR Code instance
        img = qr.make_image(fill_color="black", back_color="white")

        # Save the image file
        file_name = "password_qr.png"
        img.save(file_name)

        print(f"\nSuccess! QR code saved as '{file_name}'")
        print("⚠️  Remember: This QR code contains your unencrypted password. Keep it secure.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    create_password_qr()