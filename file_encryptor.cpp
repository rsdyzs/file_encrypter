/*
 * File Encryption Tool
 * ====================
 * Encrypts and decrypts files using XOR encryption with a password-derived key.
 * Demonstrates: file I/O, string manipulation, CLI args, basic cryptography concepts.
 *
 * Compile:  g++ -o encrypt file_encryptor.cpp
 * Usage:
 *   ./encrypt --encrypt secret.txt mypassword
 *   ./encrypt --decrypt secret.txt.enc mypassword
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cstring>

// ─────────────────────────────────────────────
// KEY DERIVATION
// Stretches a short password into a longer key
// using a simple but effective mixing technique
// ─────────────────────────────────────────────

std::vector<unsigned char> deriveKey(const std::string& password, size_t keyLength) {
    std::vector<unsigned char> key(keyLength);
    for (size_t i = 0; i < keyLength; i++) {
        // Mix password bytes with position to create varied key material
        key[i] = static_cast<unsigned char>(
            password[i % password.size()] ^ (i * 31 + 7)
        );
    }
    return key;
}

// ─────────────────────────────────────────────
// XOR ENCRYPT / DECRYPT
// XOR is symmetric: encrypt and decrypt are
// the same operation with the same key
// ─────────────────────────────────────────────

std::vector<unsigned char> xorCipher(
    const std::vector<unsigned char>& data,
    const std::string& password
) {
    std::vector<unsigned char> key = deriveKey(password, data.size());
    std::vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key[i];
    }
    return result;
}

// ─────────────────────────────────────────────
// FILE HELPERS
// ─────────────────────────────────────────────

std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// ─────────────────────────────────────────────
// MAGIC HEADER
// Stamped at the start of encrypted files so
// we can detect if a file was encrypted by
// this tool (and catch wrong passwords early)
// ─────────────────────────────────────────────

const std::string MAGIC = "ENC1";  // 4-byte signature

std::vector<unsigned char> addHeader(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> result;
    for (char c : MAGIC) result.push_back(static_cast<unsigned char>(c));
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

bool hasHeader(const std::vector<unsigned char>& data) {
    if (data.size() < MAGIC.size()) return false;
    return std::string(data.begin(), data.begin() + MAGIC.size()) == MAGIC;
}

std::vector<unsigned char> stripHeader(const std::vector<unsigned char>& data) {
    return std::vector<unsigned char>(data.begin() + MAGIC.size(), data.end());
}

// ─────────────────────────────────────────────
// ENCRYPT
// ─────────────────────────────────────────────

void encryptFile(const std::string& inputPath, const std::string& password) {
    std::cout << "[*] Reading file: " << inputPath << std::endl;
    auto data = readFile(inputPath);

    if (hasHeader(data)) {
        std::cerr << "[!] This file appears to already be encrypted." << std::endl;
        return;
    }

    std::cout << "[*] Encrypting (" << data.size() << " bytes)..." << std::endl;
    auto encrypted = xorCipher(data, password);
    auto withHeader = addHeader(encrypted);

    std::string outputPath = inputPath + ".enc";
    writeFile(outputPath, withHeader);

    std::cout << "[+] Encrypted file saved: " << outputPath << std::endl;
    std::cout << "[+] Original file kept.  Delete it manually if needed." << std::endl;
}

// ─────────────────────────────────────────────
// DECRYPT
// ─────────────────────────────────────────────

void decryptFile(const std::string& inputPath, const std::string& password) {
    std::cout << "[*] Reading file: " << inputPath << std::endl;
    auto data = readFile(inputPath);

    if (!hasHeader(data)) {
        std::cerr << "[!] This file was not encrypted by this tool (missing header)." << std::endl;
        return;
    }

    auto withoutHeader = stripHeader(data);
    std::cout << "[*] Decrypting (" << withoutHeader.size() << " bytes)..." << std::endl;
    auto decrypted = xorCipher(withoutHeader, password);

    // Remove .enc extension for output
    std::string outputPath = inputPath;
    if (outputPath.size() > 4 && outputPath.substr(outputPath.size() - 4) == ".enc") {
        outputPath = outputPath.substr(0, outputPath.size() - 4);
    } else {
        outputPath += ".decrypted";
    }

    writeFile(outputPath, decrypted);
    std::cout << "[+] Decrypted file saved: " << outputPath << std::endl;
}

// ─────────────────────────────────────────────
// USAGE / HELP
// ─────────────────────────────────────────────

void printUsage(const std::string& programName) {
    std::cout << "\nFile Encryption Tool\n";
    std::cout << "====================\n";
    std::cout << "Usage:\n";
    std::cout << "  " << programName << " --encrypt <file> <password>\n";
    std::cout << "  " << programName << " --decrypt <file.enc> <password>\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " --encrypt notes.txt mysecretpass\n";
    std::cout << "  " << programName << " --decrypt notes.txt.enc mysecretpass\n\n";
    std::cout << "Notes:\n";
    std::cout << "  - Encrypted files get a .enc extension\n";
    std::cout << "  - Use the SAME password to decrypt\n";
    std::cout << "  - Works on any file type (text, images, etc.)\n\n";
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printUsage(argv[0]);
        return 1;
    }

    std::string mode     = argv[1];
    std::string filepath = argv[2];
    std::string password = argv[3];

    if (password.empty()) {
        std::cerr << "[!] Password cannot be empty.\n";
        return 1;
    }

    try {
        if (mode == "--encrypt") {
            encryptFile(filepath, password);
        } else if (mode == "--decrypt") {
            decryptFile(filepath, password);
        } else {
            std::cerr << "[!] Unknown mode: " << mode << "\n";
            printUsage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
