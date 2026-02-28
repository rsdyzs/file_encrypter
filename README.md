# 🔒 File Encryption Tool

A C++ command-line tool that encrypts and decrypts any file using a password. Built to demonstrate file I/O, binary data handling, and basic cryptography concepts.

## How to compile & run
```bash
# Compile
g++ -o encrypt file_encryptor.cpp

# Encrypt a file
./encrypt --encrypt secret.txt mypassword

# Decrypt it back
./encrypt --decrypt secret.txt.enc mypassword
```

## How it works
- Derives a key from your password using a mixing function
- Applies **XOR cipher** byte-by-byte — a foundational concept in symmetric encryption
- Stamps a 4-byte magic header (`ENC1`) so the tool can detect already-encrypted files and catch wrong passwords early
- Works on **any file type** — text, images, PDFs, etc.

## Concepts demonstrated
- Binary file I/O (`ifstream`/`ofstream` with `ios::binary`)
- Vectors of `unsigned char` for byte-level data manipulation
- Key derivation from a passphrase
- Command-line argument parsing (`argc`/`argv`)
- Error handling with `try/catch`

## Skills shown on your resume
> *"Built a C++ file encryption tool implementing XOR cipher with password-derived key generation and binary file I/O — applying cryptography fundamentals from CodePath CYB 101."*
