// sveil_extract.c

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN  // Prevents winsock.h from being included by windows.h

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <zlib.h>
#pragma comment(lib, "zlibstat.lib")

#include <Shlwapi.h>  // For PathCombine
#pragma comment(lib, "Shlwapi.lib")

#include "sveil_extract.h"
#include "sveil_common.h"
#include "sveil_png_utils.h"

// Include BCrypt for cryptographic functions
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#define PNG_SIGNATURE_SIZE 8
#define CHUNK_HEADER_SIZE 8  // Length (4 bytes) + Type (4 bytes)
#define CHUNK_CRC_SIZE 4
#define MAGIC_NUMBER 0xDEADBEEF

// Function prototypes for decryption
static int decrypt_data(const unsigned char* encrypted_data, size_t encrypted_len, const TCHAR* password,
    unsigned char** plaintext, size_t* plaintext_len);
static int derive_key_from_password(const TCHAR* password, unsigned char* salt, unsigned char** key, DWORD* key_len);

int sveil_extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password,
    TCHAR* extracted_file_name) {
    unsigned char* png_data = NULL;
    size_t png_size = 0;
    unsigned char* idat_data = NULL;
    size_t idat_size = 0;
    int result = -1;

    unsigned char* uncompressed_data = NULL;
    size_t uncompressed_size = 0;

    FILE* fp = NULL;

    // Declare and initialize pointers at the beginning
    unsigned char* encrypted_data = NULL;
    size_t encrypted_data_size = 0;

    unsigned char* decrypted_data = NULL;
    size_t decrypted_data_size = 0;

    char* filename_utf8 = NULL;
    TCHAR* filename_tchar = NULL;

    size_t pos = 0;
    int found = 0;

    // Read the PNG file into memory
    fp = _tfopen(png_path, _T("rb"));
    if (!fp) {
        set_sveil_error_message(_T("Failed to open PNG file: %s"), png_path);
        goto cleanup;
    }

    fseek(fp, 0, SEEK_END);
    png_size = ftell(fp);
    rewind(fp);
    png_data = (unsigned char*)malloc(png_size);
    if (!png_data) {
        set_sveil_error_message(_T("Memory allocation failed for PNG data."));
        fclose(fp);
        fp = NULL;
        goto cleanup;
    }
    if (fread(png_data, 1, png_size, fp) != png_size) {
        set_sveil_error_message(_T("Failed to read PNG file."));
        fclose(fp);
        fp = NULL;
        free(png_data);
        png_data = NULL;
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Collect IDAT data
    if (collect_idat_chunks(png_data, png_size, &idat_data, &idat_size, NULL, NULL) != 0) {
        set_sveil_error_message(_T("Failed to collect IDAT chunks."));
        goto cleanup;
    }

    // Decompress the IDAT data
    if (uncompress_idat_data(idat_data, idat_size, &uncompressed_data, &uncompressed_size) != 0) {
        set_sveil_error_message(_T("Failed to decompress IDAT data."));
        goto cleanup;
    }

    free(png_data);
    png_data = NULL;
    free(idat_data);
    idat_data = NULL;

    // Search for the hidden data using the magic number
    while (pos + sizeof(uint32_t) <= uncompressed_size) {
        uint32_t magic_number = ntohl(*(uint32_t*)(uncompressed_data + pos));

        if (magic_number == MAGIC_NUMBER) {
            pos += sizeof(uint32_t);

            // Read encrypted data length
            if (pos + sizeof(uint32_t) > uncompressed_size) break;
            uint32_t encrypted_data_length = ntohl(*(uint32_t*)(uncompressed_data + pos));
            pos += sizeof(uint32_t);

            // Read encrypted data
            if (pos + encrypted_data_length > uncompressed_size) break;
            encrypted_data_size = encrypted_data_length;
            encrypted_data = (unsigned char*)malloc(encrypted_data_size);
            if (!encrypted_data) {
                set_sveil_error_message(_T("Memory allocation failed for encrypted data."));
                goto cleanup;
            }
            memcpy(encrypted_data, uncompressed_data + pos, encrypted_data_size);
            pos += encrypted_data_size;

            // Decrypt the data
            if (decrypt_data(encrypted_data, encrypted_data_size, password, &decrypted_data, &decrypted_data_size) != 0) {
                set_sveil_error_message(_T("Failed to decrypt data. Incorrect password or data corrupted."));
                goto cleanup;
            }

            free(encrypted_data);
            encrypted_data = NULL;

            // Parse the decrypted data to extract the filename and hidden data
            unsigned char* ptr = decrypted_data;
            size_t remaining_size = decrypted_data_size;

            // Read filename length
            if (remaining_size < sizeof(unsigned int)) {
                set_sveil_error_message(_T("Insufficient data for filename length."));
                goto cleanup;
            }
            unsigned int filename_length = 0;
            memcpy(&filename_length, ptr, sizeof(unsigned int));
            ptr += sizeof(unsigned int);
            remaining_size -= sizeof(unsigned int);

            // Read filename in UTF-8
            if (remaining_size < filename_length) {
                set_sveil_error_message(_T("Insufficient data for filename."));
                goto cleanup;
            }
            filename_utf8 = (char*)malloc(filename_length + 1); // +1 for null terminator
            if (!filename_utf8) {
                set_sveil_error_message(_T("Memory allocation failed for filename."));
                goto cleanup;
            }
            memcpy(filename_utf8, ptr, filename_length);
            filename_utf8[filename_length] = '\0'; // Null-terminate
            ptr += filename_length;
            remaining_size -= filename_length;

            // Convert filename from UTF-8 to TCHAR
            int filename_tchar_length = MultiByteToWideChar(CP_UTF8, 0, filename_utf8, -1, NULL, 0);
            if (filename_tchar_length <= 0) {
                set_sveil_error_message(_T("Failed to convert filename from UTF-8."));
                goto cleanup;
            }
            filename_tchar = (TCHAR*)malloc(filename_tchar_length * sizeof(TCHAR));
            if (!filename_tchar) {
                set_sveil_error_message(_T("Memory allocation failed for filename."));
                goto cleanup;
            }
            MultiByteToWideChar(CP_UTF8, 0, filename_utf8, -1, filename_tchar, filename_tchar_length);
            free(filename_utf8);
            filename_utf8 = NULL;

            // The remaining data is the hidden file data
            size_t hidden_data_size = remaining_size;
            unsigned char* hidden_data = ptr;

            // Sanitize the filename to prevent directory traversal
            TCHAR* sanitized_filename = filename_tchar;
            for (TCHAR* p = filename_tchar; *p; ++p) {
                if (*p == _T('\\') || *p == _T('/')) {
                    sanitized_filename = p + 1;
                }
            }

            // Validate output folder
            DWORD attrs = GetFileAttributes(output_folder);
            if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                set_sveil_error_message(_T("Output folder does not exist: %s"), output_folder);
                goto cleanup;
            }

            // Use PathCombine to construct the full path
            TCHAR full_path[MAX_PATH];
            if (!PathCombine(full_path, output_folder, sanitized_filename)) {
                set_sveil_error_message(_T("Failed to combine paths."));
                goto cleanup;
            }

            // Write the hidden data to a file
            FILE* out_fp = _tfopen(full_path, _T("wb"));
            if (!out_fp) {
                set_sveil_error_message(_T("Failed to open output file: %s"), full_path);
                goto cleanup;
            }

            if (fwrite(hidden_data, 1, hidden_data_size, out_fp) != hidden_data_size) {
                set_sveil_error_message(_T("Failed to write hidden data to output file."));
                fclose(out_fp);
                out_fp = NULL;
                goto cleanup;
            }
            fclose(out_fp);
            out_fp = NULL;

            if (extracted_file_name) {
                _tcscpy_s(extracted_file_name, MAX_PATH, full_path);
            }

            found = 1;
            break;
        }
        else {
            pos += 1; // Move to the next byte and continue searching
        }
    }

    free(uncompressed_data);
    uncompressed_data = NULL;

    if (!found) {
        set_sveil_error_message(_T("No hidden data found or incorrect password."));
        goto cleanup;
    }

    result = 0;

cleanup:
    if (fp) fclose(fp);
    if (png_data) free(png_data);
    if (idat_data) free(idat_data);
    if (uncompressed_data) free(uncompressed_data);
    if (filename_utf8) free(filename_utf8);
    if (filename_tchar) free(filename_tchar);
    if (encrypted_data) free(encrypted_data);
    if (decrypted_data) {
        SecureZeroMemory(decrypted_data, decrypted_data_size);
        free(decrypted_data);
    }

    return result;
}

// Decryption function using AES-GCM
static int decrypt_data(const unsigned char* encrypted_data, size_t encrypted_len, const TCHAR* password,
    unsigned char** plaintext, size_t* plaintext_len) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    unsigned char* key = NULL;
    DWORD key_len = 0;
    unsigned char iv[12];
    DWORD iv_size = sizeof(iv);
    unsigned char tag[16];
    DWORD tag_size = sizeof(tag);
    unsigned char salt[16];
    DWORD ciphertext_len = 0;
    DWORD result_len = 0;
    const unsigned char* ciphertext = NULL;

    // Check minimum encrypted data size
    if (encrypted_len < iv_size + sizeof(salt) + tag_size) {
        set_sveil_error_message(_T("Invalid encrypted data."));
        return -1;
    }

    // Extract IV
    memcpy(iv, encrypted_data, iv_size);

    // Extract salt
    memcpy(salt, encrypted_data + iv_size, sizeof(salt));

    // Extract authentication tag
    memcpy(tag, encrypted_data + encrypted_len - tag_size, tag_size);

    // Calculate ciphertext length
    ciphertext_len = (DWORD)(encrypted_len - iv_size - sizeof(salt) - tag_size);
    ciphertext = encrypted_data + iv_size + sizeof(salt);

    // Derive key from password
    if (derive_key_from_password(password, salt, &key, &key_len) != 0) {
        set_sveil_error_message(_T("Failed to derive key from password."));
        goto cleanup;
    }

    // Open AES-GCM algorithm provider
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        set_sveil_error_message(_T("Failed to open AES algorithm provider."));
        goto cleanup;
    }

    // Set chaining mode to GCM
    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        set_sveil_error_message(_T("Failed to set chaining mode to GCM."));
        goto cleanup;
    }

    // Generate key object
    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0,
        key, key_len, 0))) {
        set_sveil_error_message(_T("Failed to generate symmetric key."));
        goto cleanup;
    }

    // Prepare the authentication info structure
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = iv_size;
    authInfo.pbTag = tag;       // Set to the expected tag from encrypted data
    authInfo.cbTag = tag_size;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;
    authInfo.pbMacContext = NULL;
    authInfo.cbMacContext = 0;
    authInfo.dwFlags = 0;

    // Calculate the required buffer size for plaintext
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertext_len, &authInfo,
        NULL, 0, NULL, 0, &result_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        set_sveil_error_message(_T("Failed to calculate plaintext size during decryption."));
        goto cleanup;
    }

    // Allocate buffer for plaintext
    *plaintext = (unsigned char*)malloc(result_len);
    if (!*plaintext) {
        set_sveil_error_message(_T("Memory allocation failed for plaintext."));
        goto cleanup;
    }

    // Perform decryption
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertext_len, &authInfo,
        NULL, 0, *plaintext, result_len, &result_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        set_sveil_error_message(_T("Failed to decrypt data. The password may be incorrect or the data may be corrupted."));
        free(*plaintext);
        *plaintext = NULL;
        goto cleanup;
    }

    *plaintext_len = result_len;

    // Success
    status = STATUS_SUCCESS;

cleanup:
    SecureZeroMemory(key, key_len);
    if (key) free(key);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAesAlg) BCryptCloseAlgorithmProvider(hAesAlg, 0);

    return BCRYPT_SUCCESS(status) ? 0 : -1;
}

// Key derivation function using PBKDF2
static int derive_key_from_password(const TCHAR* password, unsigned char* salt, unsigned char** key, DWORD* key_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD password_len = 0;
#ifdef UNICODE
    password_len = (DWORD)(wcslen(password) * sizeof(WCHAR));
#else
    password_len = (DWORD)(strlen(password));
#endif
    DWORD derived_key_len = 32; // AES-256 requires a 256-bit key

    *key = (unsigned char*)malloc(derived_key_len);
    if (!*key) {
        set_sveil_error_message(_T("Memory allocation failed for derived key."));
        goto cleanup;
    }

    // Open the algorithm provider
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        set_sveil_error_message(_T("Failed to open algorithm provider for key derivation."));
        goto cleanup;
    }

    // Derive the key using PBKDF2
    if (!BCRYPT_SUCCESS(status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, password_len,
        salt, 16, 100000, *key, derived_key_len, 0))) {
        set_sveil_error_message(_T("Failed to derive key using PBKDF2."));
        goto cleanup;
    }

    *key_len = derived_key_len;

    // Success
    status = STATUS_SUCCESS;

cleanup:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status) && *key) {
        free(*key);
        *key = NULL;
    }
    return BCRYPT_SUCCESS(status) ? 0 : -1;
}
