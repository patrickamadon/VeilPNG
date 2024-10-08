=======================================
              VeilPNG
=======================================

VeilPNG is a utility designed to securely hide sensitive data within PNG images using strong encryption and compression techniques. It allows users to embed any file or directory into a PNG image by compressing the data and encrypting it with a password using AES-256-GCM encryption. The encryption key is derived from the password using PBKDF2 with HMAC-SHA256, utilizing a unique salt and high iteration count to enhance security against brute-force attacks. The encrypted data is stored within a custom ancillary chunk in the PNG file format, ensuring the image remains valid while concealing the hidden content. Users can later extract the hidden file by providing the correct password, which also verifies data integrity through an HMAC-SHA256 hash.

---------------------------------------

TABLE OF CONTENTS:

1. Features
2. Technical Overview
   - Data Embedding Process
   - Data Extraction Process
3. Security Considerations
4. Installation
5. Usage Instructions
   - Embedding Data into a PNG Image
   - Extracting Data from a PNG Image
6. Limitations
7. License
8. Contact Information

---------------------------------------

1. FEATURES:

- Strong Encryption (AES-256-GCM)
- Secure Key Derivation (PBKDF2 with HMAC-SHA256)
- Data Integrity Verification (HMAC-SHA256)
- Custom PNG Chunk for Data Storage
- Compression for Reduced Size
- Random Padding for Additional Security
- Password Strength Validation

---------------------------------------

2. TECHNICAL OVERVIEW:

### Data Embedding Process:
1. Input Validation: Ensures fields are filled and passwords are strong.
2. Data Reading: Reads the file or directory to be hidden.
3. File Name Handling: Converts file name to UTF-8 and stores its length.
4. Data Packaging: Combines file name and data into a buffer.
5. Random Padding: Adds random padding to the buffer.
6. Compression: Compresses the buffer using zlib.
7. HMAC Generation: Generates HMAC-SHA256 for data integrity.
8. Encryption: Encrypts the data using AES-256-GCM.
9. PNG Modification: Embeds the encrypted data into a custom ancillary PNG chunk.
10. Output: Writes the modified PNG to the specified output file.

### Data Extraction Process:
1. Input Validation: Ensures fields are filled.
2. PNG Reading: Reads the PNG data.
3. Chunk Extraction: Extracts custom ancillary chunk from PNG.
4. Decryption: Decrypts the data using AES-256-GCM.
5. Integrity Verification: Verifies HMAC-SHA256 for data integrity.
6. Decompression: Decompresses the data.
7. Data Reconstruction: Extracts the original file name and data.
8. Output: Writes the extracted data to the specified output folder.

---------------------------------------

3. SECURITY CONSIDERATIONS:

- **Encryption**: Uses AES-256-GCM for encryption and integrity.
- **Key Derivation**: Uses PBKDF2 with HMAC-SHA256, 16-byte salt, and 100,000 iterations.
- **Random Padding**: Prevents size analysis by adding random padding.
- **HMAC Verification**: Ensures data integrity with HMAC-SHA256.
- **Password Strength**: Requires strong passwords with complexity.
- **Secure Memory Handling**: Passwords and decrypted data are securely erased from memory.
- **Timing Attack Mitigation**: Introduces delays on decryption failure to prevent timing attacks.

---------------------------------------

4. INSTALLATION:

### Prerequisites:
- **OS**: Windows 7 or later.
- **Dependencies**: No additional installations required; all dependencies are statically linked.

### Steps:
1. **Download**: Obtain the `VeilPNGInstaller.msi`.
2. **Run Installer**: Double-click to start the installation process.
3. **Installation Wizard**: Follow the on-screen instructions.
4. **Completion**: Once installed, the application is ready to use.

---------------------------------------

5. USAGE INSTRUCTIONS:

### Embedding Data into a PNG Image:
1. **Launch VeilPNG**.
2. **Select PNG File**: Browse for the PNG image.
3. **Select Hidden File**: Browse for the file to hide.
4. **Enter Password**: Input a strong password.
5. **Create Veil**: Click the "Create Veil" button.
6. **Result**: The PNG file will now contain the hidden data.

### Extracting Data from a PNG Image:
1. **Launch VeilPNG**.
2. **Select PNG File**: Browse for the PNG image containing the hidden data.
3. **Enter Password**: Input the correct password.
4. **Extract Veil**: Click the "Extract Veil" button.
5. **Result**: The hidden file is extracted to the output folder.

---------------------------------------

6. LIMITATIONS:

- Large files may result in oversized PNG images.
- Password recovery is impossible; keep your password secure.
- Some image editors may remove the custom chunk when modifying the PNG.
- Currently, VeilPNG supports only Windows OS.

---------------------------------------

7. LICENSE:

MIT License

Copyright (c) [2024] [VeilPNG - @amadon]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------

8. CONTACT INFORMATION:

@Amadon

---------------------------------------

DISCLAIMER: VeilPNG is intended for lawful use only. The author is not responsible for any misuse of this application.

---------------------------------------

