# Secure Password Manager - Built by Claude 3.5

A simple and secure password manager built using Python and Tkinter by Claude.

## Features

- **Password Generation**: Generate secure passwords with customizable options (uppercase, lowercase, digits, special characters).
- **Encrypted Storage**: Passwords are stored in an encrypted file using PBKDF2 and Fernet encryption.
- **Master Passkey**: Secure access using a user-defined master passkey.
- **View & Copy Passwords**: Easily retrieve and copy stored passwords.
- **User-Friendly UI**: Simple and interactive Tkinter-based GUI.

## Installation

### Prerequisites

Ensure you have Python installed (Python 3.6 or higher recommended). Also, install the required dependencies using:

```sh
pip install pyperclip cryptography
```

## Usage

1. **Run the Application**
   ```sh
   python main.py
   ```
2. On first launch, set a master passkey.
3. Generate passwords and save them securely.
4. Use the passkey on subsequent launches to access stored passwords.

## Encryption Details

- **PBKDF2HMAC**: Used to derive an encryption key from the master passkey.
- **Fernet Encryption**: Encrypts and decrypts stored passwords.

## Notes

- The application does **not** store the master passkey; losing it means losing access to stored passwords.
- For security reasons, ensure your system is protected when using this application.

## License

This project is licensed under the MIT License.
