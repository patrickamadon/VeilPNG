VeilPNG 
=================

VeilPNG is a powerful utility designed to securely hide sensitive data within PNG images using strong 
encryption and compression techniques. It allows you to embed any file into a PNG image by compressing the 
data and encrypting it with a password using AES-256-GCM encryption. The encryption key is derived from your 
password using PBKDF2 with HMAC-SHA256, utilizing a unique salt and a high iteration count to enhance security 
against brute-force attacks.

The encrypted data is stored within a custom ancillary chunk in the PNG file format, ensuring the image 
remains valid while concealing the hidden content. You can later extract the hidden file by providing the correct 
password, which also verifies data integrity through an HMAC-SHA256 hash.

sVeil is a variant of VeilPNG that embeds hidden data directly into the deflate stream of the PNG image's IDAT 
chunk. This method allows for secure storage of hidden files within the PNG image without using custom ancillary 
chunks, enhancing stealth. The hidden data is appended to the trailing data of the deflate stream, ensuring that 
the PNG remains valid according to the PNG specification.

---------------------------------------

TABLE OF CONTENTS:

1. Features
2. Technical Overview
   - Data Embedding Process
   - Data Extraction Process
3. When to Use VeilPNG and When to Use sVeil
4. Security Considerations
5. Installation
6. Usage Instructions
   - Embedding Data into a PNG Image
   - Extracting Data from a PNG Image
7. Limitations
8. License
9. Contact Information

---------------------------------------

1. FEATURES:

- Strong Encryption (AES-256-GCM)
- Secure Key Derivation (PBKDF2 with HMAC-SHA256)
- Data Integrity Verification (HMAC-SHA256)
- Custom PNG Chunk for Data Storage (VeilPNG)
- Embedding Data into Deflate Stream (sVeil)
- Compression for Reduced Size
- Random Padding for Additional Security
- Password Strength Validation

---------------------------------------

2. TECHNICAL OVERVIEW:

### Data Embedding Process:

#### VeilPNG:

1. **Input Validation**: Ensures fields are filled and passwords are strong.
2. **Data Reading**: Reads the file to be hidden.
3. **File Name Handling**: Converts file name to UTF-8 and stores its length.
4. **Data Packaging**: Combines file name and data into a buffer.
5. **Compression**: Compresses the buffer using zlib.
6. **Encryption**: Encrypts the compressed data using AES-256-GCM.
7. **HMAC Generation**: Generates an HMAC-SHA256 for data integrity.
8. **PNG Modification**: Embeds the encrypted data into a custom ancillary PNG chunk.
9. **Output**: Writes the modified PNG to the specified output file.

#### sVeil:

1. **Input Validation**: Ensures fields are filled and passwords are strong.
2. **Data Reading**: Reads the file to be hidden.
3. **File Name Handling**: Converts file name to UTF-8 and stores its length.
4. **Data Packaging**: Combines file name and data into a buffer.
5. **Compression**: Compresses the buffer using zlib.
6. **Encryption**: Encrypts the compressed data using AES-256-GCM.
7. **PNG Modification**: Appends the hidden data directly into the deflate stream of the IDAT chunk.
8. **Output**: Writes the modified PNG to the specified output file.

### Data Extraction Process:

#### VeilPNG:

1. **Input Validation**: Ensures fields are filled.
2. **PNG Reading**: Reads the PNG data.
3. **Chunk Extraction**: Extracts custom ancillary chunk from PNG.
4. **Decryption**: Decrypts the data using AES-256-GCM.
5. **Integrity Verification**: Verifies HMAC-SHA256 for data integrity.
6. **Decompression**: Decompresses the data.
7. **Data Reconstruction**: Extracts the original file name and data.
8. **Output**: Writes the extracted data to the specified output folder.

#### sVeil:

1. **Input Validation**: Ensures fields are filled.
2. **PNG Reading**: Reads the PNG data.
3. **Deflate Stream Parsing**: Decompresses the IDAT chunk's data to access the appended hidden data.
4. **Data Extraction**: Searches for the hidden data within the decompressed stream.
5. **Decryption**: Decrypts the data using AES-256-GCM.
6. **Decompression**: Decompresses the data (if additional compression was applied).
7. **Data Reconstruction**: Extracts the original file name and data.
8. **Output**: Writes the extracted data to the specified output folder.

---------------------------------------

3. WHEN TO USE VEILPNG AND WHEN TO USE SVEIL:

### VeilPNG

Use VeilPNG when:

- **Embedding Larger Files**: Ideal for hiding larger files or more data efficiently.
- **Image Integrity is Critical**: The image must remain visually intact without any corruption.
- **Maximum Compatibility**: The PNG file should remain valid and compatible with all image viewers and editors.
- **Strong Security Measures**: Requires encryption and data integrity verification using AES-256-GCM and HMAC-SHA256.
- **Avoiding Image Corruption**: Any image corruption is unacceptable for your use case.

### sVeil

Use sVeil when:

- **Maximum Stealth is Required**: Embeds data directly into the deflate stream for enhanced concealment.
- **Hiding Smaller Amounts of Data**: Best suited for smaller files to minimize changes in image size.
- **Custom Chunk Removal Risk**: There's a risk that custom chunks may be removed by image editors or web services.
- **Acceptable Minor Image Changes**: Slight image modifications are acceptable for your use case.
- **Bypassing Basic Analysis**: Embedding within the deflate stream makes hidden data less detectable by standard analysis tools.

---------------------------------------

4. SECURITY CONSIDERATIONS:

- **Encryption**: Utilizes AES-256-GCM for robust encryption and data integrity.
- **Key Derivation**: Employs PBKDF2 with HMAC-SHA256, a 16-byte salt, and 100,000 iterations for secure key derivation.
- **Data Integrity**: Uses HMAC-SHA256 to verify that the data has not been altered.
- **Password Strength**: Enforces strong passwords to prevent unauthorized access.
- **Secure Memory Handling**: Sensitive data is securely erased from memory after use.
- **Random Padding**: Adds randomness to prevent size-based analysis (in VeilPNG).
- **Stealth Techniques**: sVeil embeds data within the deflate stream to enhance stealth.

---------------------------------------

5. INSTALLATION:

### Prerequisites:

- **Operating System**: Windows 7 or later (64-bit recommended).
- **Dependencies**: All required libraries are included; no additional installations needed.

### Installation Steps:

1. **Download**: Obtain the `VeilPNGInstaller.msi` file from the [releases page](#).
2. **Run Installer**: Double-click the installer to start the setup process.
3. **Follow Instructions**: Proceed through the installation wizard by following the on-screen prompts.
4. **Completion**: After installation, you can launch VeilPNG from the Start Menu or desktop shortcut.

---------------------------------------

6. USAGE INSTRUCTIONS:

### Embedding Data into a PNG Image:

#### Using VeilPNG:

1. **Launch VeilPNG**: Open the application.
2. **Select PNG File**: Click on the "Browse..." button next to "PNG File" and choose your carrier PNG image.
3. **Select Hidden File**: Click on the "Browse..." button next to "Hidden File" and select the file you wish to hide.
4. **Enter Password**: Input a strong password that meets the password requirements.
5. **Show Password (Optional)**: Check "Show Password" if you want to see the password as you type.
6. **Create Veil**: Click the "Create Veil" button and choose a destination for the output PNG.
7. **Result**: The PNG file now contains the hidden data using a custom ancillary chunk.

#### Using sVeil:

1. **Launch VeilPNG**: Open the application (sVeil functionality is integrated).
2. **Select PNG File**: Click on the "Browse..." button next to "PNG File" and choose your carrier PNG image.
3. **Select Hidden File**: Click on the "Browse..." button next to "Hidden File" and select the file you wish to hide.
4. **Enter Password**: Input a strong password that meets the password requirements.
5. **Show Password (Optional)**: Check "Show Password" if you want to see the password as you type.
6. **Create sVeil**: Click the "Create sVeil" button and choose a destination for the output PNG.
7. **Result**: The PNG file now contains the hidden data embedded directly into the deflate stream.

### Extracting Data from a PNG Image:

1. **Launch VeilPNG**: Open the application.
2. **Select PNG File**: Click on the "Browse..." button next to "PNG File" and select the PNG image containing the hidden data.
3. **Enter Password**: Input the password used during embedding.
4. **Show Password (Optional)**: Check "Show Password" if you want to see the password as you type.
5. **Extract Veil**: Click the "Extract Veil" button.
6. **Choose Output Folder**: Select the folder where you want to save the extracted file.
7. **Result**: The hidden file is extracted to the specified output folder.

---------------------------------------

7. LIMITATIONS:

- **Large Files**: Embedding very large files may result in significantly increased PNG sizes.
- **Password Recovery**: Passwords are not stored; if you forget your password, the data cannot be recovered.
- **Image Editors**: Some image editors or platforms may strip custom chunks (VeilPNG) or alter the deflate stream (sVeil), potentially removing the hidden data.
- **Image Compatibility**: sVeil may cause minor image alterations that could affect compatibility with some image viewers.
- **Platform Support**: Currently supports only Windows OS.

---------------------------------------

8. LICENSE:

VeilPNG is licensed under the MIT License.

---------------------------------------

9. CONTACT INFORMATION:

For questions, support, or contributions, please contact:

- **Author**: [Amadon](https://github.com/Amadon)
- **Email**: [amadon@example.com](mailto:amadon@example.com)
- **GitHub Repository**: [VeilPNG](https://github.com/Amadon/VeilPNG)

---------------------------------------

DISCLAIMER: VeilPNG and sVeil are intended for lawful use only. The author is not responsible for any misuse of these applications. By using this software, you agree to the terms and conditions outlined in the MIT License.

---

**Enjoy using VeilPNG to secure your data!**

---

## Additional Notes

- **Twitter Users**: If you plan to share your PNG images on Twitter, ensure your images are within Twitter's size limits—900 pixels (width/height) and a total file size (image + hidden data) below 5 MB to avoid automatic conversion to JPEG format, which would strip the hidden data.
- **Password Requirements**: For maximum security, use a password that includes uppercase and lowercase letters, numbers, and special characters, and is at least 12 characters long.

## Frequently Asked Questions (FAQ)

**Q1: Can I hide multiple files at once?**

- **A**: Currently, VeilPNG supports embedding one file at a time. To hide multiple files, you can compress them into a single archive (e.g., ZIP) before embedding.

**Q2: Is there a size limit for the file I can hide?**

- **A**: The size is limited by the maximum file size that can be handled by the PNG format and practical considerations regarding the resulting image size.

**Q3: Can I use my own images as carrier PNGs?**

- **A**: Yes, you can use any valid PNG image as the carrier for your hidden data.

**Q4: Is the hidden data detectable by analysis tools?**

- **A**: While VeilPNG and sVeil employ methods to conceal data, advanced forensic tools may detect anomalies. sVeil offers enhanced stealth by embedding data within the deflate stream.

**Q5: What happens if someone tries to extract data without the correct password?**

- **A**: Extraction will fail, and the hidden data will remain secure. Multiple incorrect attempts do not compromise the encryption.

**Q6: What are the Twitter size limits for posting images without conversion to JPEG?**

- **A**: For Twitter, ensure your PNG images are no larger than 900 pixels in either width or height and keep the combined file size (image + hidden data) below 5 MB. Exceeding these limits may cause Twitter to convert the image to JPEG, which would remove any hidden data.

