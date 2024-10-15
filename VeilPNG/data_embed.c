// data_embed.c

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>   // Include for file I/O functions
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <time.h>    // Include time.h for time()

// Include Windows headers without conflicting macros
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include "data_embed.h"
#include "png_handler.h"
#include "encryption.h"
#include <zlib.h>

// Define the custom chunk type (must be 4 characters)
#define CHUNK_TYPE "cUsR"  // Use a fixed chunk type

// Static buffer to hold error messages
static TCHAR last_error_message[512];

const TCHAR* get_last_error_message() {
    return last_error_message;
}

// Function to embed data into PNG
int embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password) {
    // Seed the random number generator
    srand((unsigned int)time(NULL));

    // Step 1: Read original PNG data
    unsigned char* png_data = NULL;
    size_t png_size = 0;
    if (read_file(png_path, &png_data, &png_size) != 0) {
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Error reading PNG file."));
        return -1;
    }

    // Step 2: Read data to embed
    unsigned char* data = NULL;
    size_t data_size = 0;
    if (read_file(data_path, &data, &data_size) != 0) {
        free(png_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Error reading data file."));
        return -1;
    }

    // Step 3: Extract the file name from data_path
    const TCHAR* file_name = _tcsrchr(data_path, _T('\\'));
    if (file_name == NULL) file_name = _tcsrchr(data_path, _T('/'));
    if (file_name != NULL) file_name++; else file_name = data_path;  // Move past the last path separator

    // Step 4: Convert file_name to UTF-8
    char* file_name_utf8 = NULL;
    int file_name_utf8_len = 0;

#ifdef UNICODE
    file_name_utf8_len = WideCharToMultiByte(CP_UTF8, 0, file_name, -1, NULL, 0, NULL, NULL);
    if (file_name_utf8_len == 0) {
        free(png_data);
        free(data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Error converting file name to UTF-8."));
        return -1;
    }

    file_name_utf8 = (char*)malloc(file_name_utf8_len);
    if (file_name_utf8 == NULL) {
        free(png_data);
        free(data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }
    WideCharToMultiByte(CP_UTF8, 0, file_name, -1, file_name_utf8, file_name_utf8_len, NULL, NULL);
#else
    file_name_utf8_len = strlen(file_name) + 1;
    file_name_utf8 = (char*)malloc(file_name_utf8_len);
    if (file_name_utf8 == NULL) {
        free(png_data);
        free(data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }
    strcpy_s(file_name_utf8, file_name_utf8_len, file_name);
#endif

    unsigned int file_name_length = (unsigned int)(file_name_utf8_len - 1);

    // Step 5: Combine file name length, file name, and data into a buffer
    size_t total_buffer_size = sizeof(unsigned int) + file_name_length + data_size;
    unsigned char* buffer = (unsigned char*)malloc(total_buffer_size);
    if (buffer == NULL) {
        free(png_data);
        free(data);
        free(file_name_utf8);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }

    unsigned char* ptr = buffer;
    size_t remaining_size = total_buffer_size;

    // Copy file_name_length
    if (remaining_size < sizeof(unsigned int)) {
        free(png_data);
        free(data);
        free(file_name_utf8);
        free(buffer);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Insufficient buffer size for file_name_length."));
        return -1;
    }
    memcpy(ptr, &file_name_length, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    remaining_size -= sizeof(unsigned int);

    // Copy file_name_utf8
    if (remaining_size < file_name_length) {
        free(png_data);
        free(data);
        free(file_name_utf8);
        free(buffer);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Insufficient buffer size for file_name."));
        return -1;
    }
    memcpy(ptr, file_name_utf8, file_name_length);
    ptr += file_name_length;
    remaining_size -= file_name_length;

    // Copy data
    if (remaining_size < data_size) {
        free(png_data);
        free(data);
        free(file_name_utf8);
        free(buffer);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Insufficient buffer size for data."));
        return -1;
    }
    memcpy(ptr, data, data_size);
    ptr += data_size;
    remaining_size -= data_size;

    free(data);
    free(file_name_utf8);

    // Step 6: Add random padding
    size_t padding_size = rand() % 256;  // Random padding up to 255 bytes
    unsigned char* padded_buffer = (unsigned char*)malloc(total_buffer_size + padding_size);
    if (padded_buffer == NULL) {
        free(png_data);
        free(buffer);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }

    memcpy(padded_buffer, buffer, total_buffer_size);

    // Generate random padding
    if (padding_size > 0) {
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, padded_buffer + total_buffer_size, (ULONG)padding_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            free(png_data);
            free(buffer);
            free(padded_buffer);
            _tcscpy_s(last_error_message, _countof(last_error_message), _T("Random generation failed."));
            return -1;
        }
    }

    total_buffer_size += padding_size;
    free(buffer);

    // Step 7: Compress the buffer with maximum compression level
    uLongf compressed_size = compressBound((uLong)total_buffer_size);
    unsigned char* compressed_data = (unsigned char*)malloc(compressed_size);
    if (compressed_data == NULL) {
        free(png_data);
        free(padded_buffer);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }

    int z_result = compress2(compressed_data, &compressed_size, padded_buffer, (uLong)total_buffer_size, Z_BEST_COMPRESSION);
    free(padded_buffer);
    if (z_result != Z_OK) {
        free(png_data);
        free(compressed_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Compression failed."));
        return -1;
    }

    // Step 8: Generate HMAC for integrity
    unsigned char hmac[32];  // SHA-256 digest length
    if (generate_hmac(password, compressed_data, compressed_size, hmac) != 0) {
        free(png_data);
        free(compressed_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("HMAC generation failed."));
        return -1;
    }

    // Step 9: Append HMAC to compressed data
    size_t data_with_hmac_size = compressed_size + 32;
    unsigned char* data_with_hmac = (unsigned char*)malloc(data_with_hmac_size);
    if (data_with_hmac == NULL) {
        free(png_data);
        free(compressed_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }

    // Copy compressed data
    memcpy(data_with_hmac, compressed_data, compressed_size);

    // Copy HMAC
    memcpy(data_with_hmac + compressed_size, hmac, 32);

    free(compressed_data);

    // Step 10: Encrypt the data with HMAC
    size_t encrypted_size = 0;
    unsigned char* encrypted_data = NULL;
    if (encrypt_data(data_with_hmac, data_with_hmac_size, password, &encrypted_data, &encrypted_size) != 0) {
        free(png_data);
        free(data_with_hmac);
        const TCHAR* encryption_error = get_encryption_error_message();
        _tcscpy_s(last_error_message, _countof(last_error_message), encryption_error);
        return -1;
    }

    free(data_with_hmac);

    // Step 11: Insert encrypted data into PNG
    unsigned char* new_png_data = NULL;
    size_t new_png_size = 0;
    if (insert_custom_chunk(png_data, png_size, encrypted_data, encrypted_size, CHUNK_TYPE, &new_png_data, &new_png_size) != 0) {
        free(png_data);
        free(encrypted_data);
        const TCHAR* png_error = get_png_handler_error_message();
        _tcscpy_s(last_error_message, _countof(last_error_message), png_error);
        return -1;
    }

    free(png_data);
    free(encrypted_data);

    // Step 12: Write new PNG data to file
    if (write_file(output_path, new_png_data, new_png_size) != 0) {
        free(new_png_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Failed to write output PNG file."));
        return -1;
    }

    free(new_png_data);
    // Success
    return 0;
}

// Function to extract data from PNG
int extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password, TCHAR* extracted_file_name) {
    ULONGLONG startTime = GetTickCount64();  // Start time for timing attack mitigation

    // Step 1: Read PNG data
    unsigned char* png_data = NULL;
    size_t png_size = 0;
    if (read_file(png_path, &png_data, &png_size) != 0) {
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Error reading PNG file."));
        return -1;
    }

    // Step 2: Extract custom chunk data
    unsigned char* chunk_data = NULL;
    size_t chunk_size = 0;
    if (extract_custom_chunk(png_data, png_size, CHUNK_TYPE, &chunk_data, &chunk_size) != 0) {
        free(png_data);
        const TCHAR* png_error = get_png_handler_error_message();
        _tcscpy_s(last_error_message, _countof(last_error_message), png_error);
        return -1;
    }

    free(png_data);

    // Step 3: Decrypt chunk data
    size_t decrypted_size = 0;
    unsigned char* decrypted_data = NULL;
    if (decrypt_data(chunk_data, chunk_size, password, &decrypted_data, &decrypted_size) != 0) {
        free(chunk_data);

        // Ensure consistent response time
        ULONGLONG elapsedTime = GetTickCount64() - startTime;
        ULONGLONG delay = (elapsedTime < 5000) ? (5000 - elapsedTime) : 0;
        Sleep((DWORD)delay);

        // Provide a generic error message
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    free(chunk_data);

    // Step 4: Verify HMAC (Integrity Check)
    if (decrypted_size < 32) {
        SecureZeroMemory(decrypted_data, decrypted_size);
        free(decrypted_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    size_t data_size = decrypted_size - 32;
    unsigned char* data_with_hmac = decrypted_data;

    unsigned char expected_hmac[32];
    memcpy(expected_hmac, data_with_hmac + data_size, 32);

    // Compute HMAC of the data
    unsigned char computed_hmac[32];
    if (generate_hmac(password, data_with_hmac, data_size, computed_hmac) != 0) {
        SecureZeroMemory(decrypted_data, decrypted_size);
        free(decrypted_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    if (memcmp(expected_hmac, computed_hmac, 32) != 0) {
        SecureZeroMemory(decrypted_data, decrypted_size);
        free(decrypted_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    // Step 5: Decompress data
    uLongf decompressed_size = (uLongf)(data_size * 10);  // Initial estimate
    unsigned char* decompressed_data = NULL;
    int z_result;
    int attempts = 0;
    const int max_attempts = 5;

    do {
        decompressed_data = (unsigned char*)malloc(decompressed_size);
        if (decompressed_data == NULL) {
            SecureZeroMemory(decrypted_data, decrypted_size);
            free(decrypted_data);
            _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
            return -1;
        }

        z_result = uncompress(decompressed_data, &decompressed_size, data_with_hmac, (uLongf)data_size);
        if (z_result == Z_BUF_ERROR) {
            // Buffer wasn't large enough, try increasing size
            free(decompressed_data);
            decompressed_size *= 2;  // Double the buffer size
            attempts++;
        }
        else if (z_result != Z_OK) {
            free(decompressed_data);
            SecureZeroMemory(decrypted_data, decrypted_size);
            free(decrypted_data);
            _tcscpy_s(last_error_message, _countof(last_error_message), _T("Decompression failed."));
            return -1;
        }
    } while (z_result == Z_BUF_ERROR && attempts < max_attempts);

    SecureZeroMemory(decrypted_data, decrypted_size);
    free(decrypted_data);

    if (z_result != Z_OK) {
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Decompression failed after multiple attempts."));
        return -1;
    }

    // Step 6: Parse the decompressed data
    unsigned char* ptr = decompressed_data;
    size_t remaining_size = decompressed_size;

    // Read file_name_length
    if (remaining_size < sizeof(unsigned int)) {
        free(decompressed_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Insufficient data for file name length."));
        return -1;
    }
    unsigned int file_name_length = 0;
    memcpy(&file_name_length, ptr, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    remaining_size -= sizeof(unsigned int);

    // Read file_name_utf8
    if (remaining_size < file_name_length) {
        free(decompressed_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Insufficient data for file name."));
        return -1;
    }
    char* file_name_utf8 = (char*)malloc(file_name_length + 1);
    if (file_name_utf8 == NULL) {
        free(decompressed_data);
        _tcscpy_s(last_error_message, _countof(last_error_message), _T("Memory allocation failure."));
        return -1;
    }
    memcpy(file_name_utf8, ptr, file_name_length);
    file_name_utf8[file_name_length] = '\0';  // Null-terminate UTF-8 string
    ptr += file_name_length;
    remaining_size -= file_name_length;

    // Convert UTF-8 file name to TCHAR
    TCHAR output_file_name[MAX_PATH] = _T("");
#ifdef UNICODE
    MultiByteToWideChar(CP_UTF8, 0, file_name_utf8, -1, output_file_name, MAX_PATH);
#else
    strcpy_s(output_file_name, MAX_PATH, file_name_utf8);
#endif
    free(file_name_utf8);

    // Step 7: Create full output file path
    _stprintf_s(extracted_file_name, MAX_PATH, _T("%s\\%s"), output_folder, output_file_name);

    // Step 8: Write extracted data to output file
    size_t file_data_size = remaining_size;
    if (write_file(extracted_file_name, ptr, file_data_size) != 0) {
        free(decompressed_data);
        const TCHAR* png_error = get_png_handler_error_message();
        _tcscpy_s(last_error_message, _countof(last_error_message), png_error);
        return -1;
    }

    free(decompressed_data);

    // Ensure consistent response time
    ULONGLONG elapsedTime = GetTickCount64() - startTime;
    ULONGLONG delay = (elapsedTime < 5000) ? (5000 - elapsedTime) : 0;
    Sleep((DWORD)delay);

    // Success
    return 0;
}
