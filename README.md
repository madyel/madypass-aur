# Madypass

Madypass is a desktop password generator for **Arch Linux** distributed through the **AUR (Arch User Repository)**. It provides a simple PyQt5 interface to generate strong passwords, copy them to the clipboard, and store them locally in encrypted form.

## Features

- Generate passwords with configurable length.
- Toggle uppercase letters, numbers, and special characters.
- Enable a dedicated **digits-only** mode.
- Save generated passwords in an encrypted local store using `cryptography.Fernet`.
- Browse saved passwords inside the application.
- Copy passwords from the main output or directly from the saved-password table.
- Delete stored passwords from the encrypted vault.

## How it works

Madypass stores its local data inside:

- `~/.generate-password/secret.key` — encryption key.
- `~/.generate-password/passwords.enc` — encrypted password entries.
- `~/.generate-password/log/password_generator.log` — application log.

Each saved password is encrypted before being written to disk.

## Dependencies

The application requires:

- Python 3
- PyQt5
- `cryptography`

On Arch Linux these dependencies are typically handled by the AUR package metadata.

## Running the application

If the package is installed from AUR, start it with:

```bash
madypass
```

If you are running it manually from the repository:

```bash
python madypass.py
```

## AUR installation example

Using an AUR helper such as `yay`:

```bash
yay -S madypass
```

## Notes

- Passwords are stored **locally** on your machine.
- Keep your home directory secure because the encryption key is also stored locally.
- This project is designed for desktop use on Arch Linux.
