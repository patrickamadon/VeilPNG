// sveil_embed.c

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <zlib.h>
#pragma comment(lib, "zlibstat.lib")

#include "sveil_embed.h"
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

// Function prototypes for encryption
static int encrypt_data(const unsigned char* plaintext, size_t plaintext_len, const TCHAR* password,
    unsigned char** encrypted_data, size_t* encrypted_len);
static int derive_key_from_password(const TCHAR* password, unsigned char* salt, unsigned char** key, DWORD* key_len);

int sveil_embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password) {
    unsigned char* png_data = NULL;
    size_t png_size = 0;
    unsigned char* idat_data = NULL;
    size_t idat_size = 0;
    size_t idat_pos = 0;
    size_t idat_total_length = 0;
    int result = -1;

    unsigned char* image_data = NULL;
    size_t image_data_size = 0;
    unsigned char* combined_data = NULL;
    size_t combined_data_size = 0;
    unsigned char* new_idat_data = NULL;
    size_t new_idat_size = 0;

    unsigned char* data_buffer = NULL;
    size_t data_size = 0;

    FILE* fp = NULL;
    FILE* data_fp = NULL;

    // Seed the random number generator
    srand((unsigned int)time(NULL));

    // Read the PNG file into memory
    fp = _tfopen(png_path, _T("rb"));
    if (!fp) {
        set_sveil_error_message(_T("Failed to open PNG file."));
        goto cleanup;
    }
    fseek(fp, 0, SEEK_END);
    png_size = ftell(fp);
    rewind(fp);
    png_data = (unsigned char*)malloc(png_size);
    if (!png_data) {
        set_sveil_error_message(_T("Memory allocation failed for PNG data."));
        fclose(fp);
        goto cleanup;
    }
    if (fread(png_data, 1, png_size, fp) != png_size) {
        set_sveil_error_message(_T("Failed to read PNG file."));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Verify PNG signature
    if (png_size < PNG_SIGNATURE_SIZE || memcmp(png_data, "\x89PNG\r\n\x1a\n", PNG_SIGNATURE_SIZE) != 0) {
        set_sveil_error_message(_T("Invalid PNG file."));
        goto cleanup;
    }

    // Collect IDAT data
    if (collect_idat_chunks(png_data, png_size, &idat_data, &idat_size, &idat_pos, &idat_total_length) != 0) {
        set_sveil_error_message(_T("Failed to collect IDAT chunks."));
        goto cleanup;
    }

    // Decompress IDAT data
    if (uncompress_idat_data(idat_data, idat_size, &image_data, &image_data_size) != 0) {
        set_sveil_error_message(_T("Failed to decompress IDAT data."));
        goto cleanup;
    }

    // Read the data file to be embedded
    data_fp = _tfopen(data_path, _T("rb"));
    if (!data_fp) {
        set_sveil_error_message(_T("Failed to open data file."));
        goto cleanup;
    }
    fseek(data_fp, 0, SEEK_END);
    data_size = ftell(data_fp);
    rewind(data_fp);
    data_buffer = (unsigned char*)malloc(data_size);
    if (!data_buffer) {
        set_sveil_error_message(_T("Memory allocation failed for data buffer."));
        fclose(data_fp);
        goto cleanup;
    }
    if (fread(data_buffer, 1, data_size, data_fp) != data_size) {
        set_sveil_error_message(_T("Failed to read data file."));
        fclose(data_fp);
        goto cleanup;
    }
    fclose(data_fp);
    data_fp = NULL;

    // Get the filename from the data_path
    const TCHAR* filename = _tcsrchr(data_path, _T('\\'));
    if (!filename) {
        filename = _tcsrchr(data_path, _T('/'));
    }
    if (!filename) {
        filename = data_path;
    }
    else {
        filename++; // Skip the path separator
    }

    // Convert filename to UTF-8
    int filename_utf8_length = WideCharToMultiByte(CP_UTF8, 0, filename, -1, NULL, 0, NULL, NULL);
    if (filename_utf8_length <= 0) {
        set_sveil_error_message(_T("Failed to convert filename to UTF-8."));
        goto cleanup;
    }
    char* filename_utf8 = (char*)malloc(filename_utf8_length);
    if (!filename_utf8) {
        set_sveil_error_message(_T("Memory allocation failed for filename."));
        goto cleanup;
    }
    WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_utf8, filename_utf8_length, NULL, NULL);
    filename_utf8_length--; // Exclude null terminator

    // Prepare the combined data buffer: [filename_length][filename][data]
    unsigned int filename_length = (unsigned int)filename_utf8_length;
    size_t plaintext_size = sizeof(unsigned int) + filename_length + data_size;
    unsigned char* plaintext = (unsigned char*)malloc(plaintext_size);
    if (!plaintext) {
        set_sveil_error_message(_T("Memory allocation failed for plaintext."));
        free(filename_utf8);
        goto cleanup;
    }

    unsigned char* ptr = plaintext;
    memcpy(ptr, &filename_length, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    memcpy(ptr, filename_utf8, filename_length);
    ptr += filename_length;
    memcpy(ptr, data_buffer, data_size);

    free(filename_utf8);
    free(data_buffer);
    data_buffer = NULL;

    // Encrypt the combined data using AES-GCM
    unsigned char* encrypted_data = NULL;
    size_t encrypted_size = 0;
    if (encrypt_data(plaintext, plaintext_size, password, &encrypted_data, &encrypted_size) != 0) {
        set_sveil_error_message(_T("Failed to encrypt data."));
        free(plaintext);
        goto cleanup;
    }
    free(plaintext);

    // Append magic number, encrypted data length, and encrypted data to the image data
    uint32_t magic_number = htonl(MAGIC_NUMBER);
    uint32_t encrypted_data_length = htonl((uint32_t)encrypted_size);

    combined_data_size = image_data_size + sizeof(uint32_t) * 2 + encrypted_size;
    combined_data = (unsigned char*)malloc(combined_data_size);
    if (!combined_data) {
        set_sveil_error_message(_T("Memory allocation failed for combined data."));
        goto cleanup;
    }

    // Copy original image data
    memcpy(combined_data, image_data, image_data_size);

    // Append magic number
    size_t offset = image_data_size;
    memcpy(combined_data + offset, &magic_number, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // Append encrypted data length
    memcpy(combined_data + offset, &encrypted_data_length, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // Append encrypted data
    memcpy(combined_data + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    combined_data_size = offset;

    free(encrypted_data);

    // Compress the combined data
    uLongf compressed_size = compressBound((uLongf)combined_data_size);
    new_idat_data = (unsigned char*)malloc(compressed_size);
    if (!new_idat_data) {
        set_sveil_error_message(_T("Memory allocation failed for new IDAT data."));
        goto cleanup;
    }

    int ret = compress2(new_idat_data, &compressed_size, combined_data, (uLongf)combined_data_size, Z_BEST_COMPRESSION);
    if (ret != Z_OK) {
        set_sveil_error_message(_T("Failed to compress combined data."));
        goto cleanup;
    }
    new_idat_size = compressed_size;

    // Replace IDAT chunks with the new data
    if (replace_idat_chunks(&png_data, &png_size, idat_pos, idat_total_length, new_idat_data, new_idat_size) != 0) {
        set_sveil_error_message(_T("Failed to replace IDAT chunks."));
        goto cleanup;
    }

    // Write the modified PNG data to the output file
    fp = _tfopen(output_path, _T("wb"));
    if (!fp) {
        set_sveil_error_message(_T("Failed to open output file."));
        goto cleanup;
    }
    if (fwrite(png_data, 1, png_size, fp) != png_size) {
        set_sveil_error_message(_T("Failed to write output PNG file."));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Success
    result = 0;

cleanup:
    if (fp) fclose(fp);
    if (data_fp) fclose(data_fp);
    if (png_data) free(png_data);
    if (idat_data) free(idat_data);
    if (data_buffer) free(data_buffer);
    if (image_data) free(image_data);
    if (combined_data) free(combined_data);
    if (new_idat_data) free(new_idat_data);

    return result;
}

// Encryption function using AES-GCM
static int encrypt_data(const unsigned char* plaintext, size_t plaintext_len, const TCHAR* password,
    unsigned char** encrypted_data, size_t* encrypted_len) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    unsigned char* key = NULL;
    DWORD key_len = 0;
    unsigned char iv[12]; // Recommended IV size for AES-GCM is 12 bytes
    DWORD iv_size = sizeof(iv);
    unsigned char tag[16]; // Authentication tag size
    DWORD tag_size = sizeof(tag);
    DWORD ciphertext_len = 0;
    DWORD result_len = 0;

    // Generate a random IV
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, iv, iv_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        set_sveil_error_message(_T("Failed to generate IV."));
        goto cleanup;
    }

    // Derive key from password
    unsigned char salt[16];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, salt, sizeof(salt), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        set_sveil_error_message(_T("Failed to generate salt."));
        goto cleanup;
    }
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
    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        set_sveil_error_message(_T("Failed to set chaining mode to GCM."));
        goto cleanup;
    }

    // Generate key object
    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, key, key_len, 0))) {
        set_sveil_error_message(_T("Failed to generate symmetric key."));
        goto cleanup;
    }

    // Prepare the authentication info structure
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = iv_size;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;
    authInfo.pbTag = tag;
    authInfo.cbTag = tag_size;
    authInfo.pbMacContext = NULL;
    authInfo.cbMacContext = 0;
    authInfo.dwFlags = 0;

    // Calculate the required buffer size for ciphertext
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plaintext_len, &authInfo, NULL, 0,
        NULL, 0, &ciphertext_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        set_sveil_error_message(_T("Failed to calculate ciphertext size."));
        goto cleanup;
    }

    // Allocate buffer for encrypted data
    *encrypted_data = (unsigned char*)malloc(iv_size + sizeof(salt) + ciphertext_len + tag_size);
    if (!*encrypted_data) {
        set_sveil_error_message(_T("Memory allocation failed for encrypted data."));
        goto cleanup;
    }

    // Copy IV and salt to the beginning of the encrypted data
    memcpy(*encrypted_data, iv, iv_size);
    memcpy(*encrypted_data + iv_size, salt, sizeof(salt));

    // Perform encryption
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plaintext_len, &authInfo,
        NULL, 0, *encrypted_data + iv_size + sizeof(salt),
        ciphertext_len, &result_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        set_sveil_error_message(_T("Failed to encrypt data."));
        free(*encrypted_data);
        *encrypted_data = NULL;
        goto cleanup;
    }

    // Append the authentication tag after the ciphertext
    memcpy(*encrypted_data + iv_size + sizeof(salt) + ciphertext_len, tag, tag_size);

    *encrypted_len = iv_size + sizeof(salt) + ciphertext_len + tag_size;

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
