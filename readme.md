# Password Vault

Password Vault is a simple password manager built using Python and Tkinter. It allows users to securely store and manage their website credentials. The application uses SQLite to store the data locally.

## Features

- Create a master password to access the vault.
- Add new website login entries (website, username, and password).
- Delete existing website login entries.
- Generate strong passwords for websites.
- Check password strength based on various criteria.
- Copy passwords to the clipboard for easy use.

## Requirements

- Python 3.x
- Tkinter (usually comes pre-installed with Python)
- SQLite3 (included with Python)

## How to Run

1. Install Python 3.x if not already installed.
2. Clone or download this repository.
3. Open a terminal or command prompt and navigate to the project directory.
4. Run the following command to start the application:


## Usage

1. Upon starting the application for the first time, you will be prompted to create a master password.
2. After setting up the master password, you will be taken to the main vault screen.
3. Use the "Add new login" button to add new website login entries. Enter the website URL, username, and password when prompted.
4. Use the "Delete" button next to each entry to remove the respective website login from the vault.
5. To generate a strong password, click on the "Generate Strong Password" button.
6. Click on the "Check Strength" button to evaluate the strength of a password.
7. To copy a password to the clipboard, click on the "Copy" button next to the respective entry.

## Note

- The application's data is stored in a local SQLite database named "password_vault.db" in the same directory as the script.
- Do not forget your master password. There is no way to recover it if lost.

## License

This project is licensed under the [MIT License](LICENSE).
