# flipa55 - Encrypted password manager for Flipper Zero

## Main features

- Encryption key derived from RFID tag data or NFC tag data
- Random tag creation
- Usernames and passwords are typed using HID keyboard device
- Passwords are protected using AES in CFB mode using 256-bit key
- Batch encryption allowing converting plaintext passwords to encrypted storage

## AI use disclaimer

AI (Gemini) was used to write parts of the codebase.
This is a hobby project where the goal was to have a functioning app in shortest time possible.

The entire NFC handling was done completely by AI agent using Antigravity CLI.

The AES cipher library and SHA256 were still written by hand and are FIPS compliant and tested against NIST test vectors.

## File format and organization

### App directories

`/ext/flipa55/data` directory contains the encrypted files.

`/ext/flipa55/plain` directory is the source for batch encryption and contains plaintext password files.

#### Plaintext password file format

Plaintext password file contains only two lines:
1. Username
2. Password

#### Encrypted password file format

Encrypted password file contains clear username on the first line.
The second "line" of the file is a binary blob with encrypted password.

## Encryption key backup

The application supports exporting the encryption key extracted from NFC or RFID tag.
The key is typed by HID keyboard as HEX data.
