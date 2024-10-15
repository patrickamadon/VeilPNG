// encryption.c

#include "encryption.h"

// Include Windows headers without conflicting macros
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <stdio.h>

#define KEY_SIZE 32  // 256-bit key for AES-256
#define IV_SIZE 12   // 96-bit nonce for AES GCM
#define SALT_SIZE 16
#define TAG_SIZE 16  // 128-bit authentication tag

// Static buffer to hold error messages
static TCHAR encryption_error_message[512];

const TCHAR* get_encryption_error_message() {
    return encryption_error_message;
}

// Function prototypes
int derive_key_iv(const TCHAR* password, unsigned char* salt, unsigned char* key, unsigned char* iv);
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
    const unsigned char* salt, size_t salt_len,
    unsigned int iterations, unsigned char* output, size_t output_len);

// Function to encrypt data
int encrypt_data(unsigned char* plaintext, size_t plaintext_len, const TCHAR* password,
    unsigned char** ciphertext, size_t* ciphertext_len) {
    NTSTATUS status;
    int ret = -1;

    unsigned char salt[SALT_SIZE];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, salt, SALT_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Random number generation failed."));
        return -1;
    }

    // Derive key and IV
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    if (derive_key_iv(password, salt, key, iv) != 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Key derivation failed."));
        return -1;
    }

    // Open algorithm provider
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to open AES algorithm provider."));
        return -1;
    }

    // Set chaining mode to GCM
    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to set chaining mode to GCM."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Generate key object
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD keyObjectSize = 0;
    DWORD result = 0;
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &result, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to get key object size."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    PUCHAR keyObject = (PUCHAR)malloc(keyObjectSize);
    if (keyObject == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectSize, key, KEY_SIZE, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to generate symmetric key."));
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Prepare the auth info structure
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = IV_SIZE;
    authInfo.pbTag = (PUCHAR)malloc(TAG_SIZE);
    if (authInfo.pbTag == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    authInfo.cbTag = TAG_SIZE;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    // Allocate ciphertext buffer
    *ciphertext_len = plaintext_len;
    *ciphertext = (unsigned char*)malloc(*ciphertext_len + SALT_SIZE + IV_SIZE + TAG_SIZE);
    if (*ciphertext == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        free(authInfo.pbTag);
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Encrypt
    ULONG cbResult = 0;
    if (!BCRYPT_SUCCESS(status = BCryptEncrypt(hKey, plaintext, (ULONG)plaintext_len, &authInfo, NULL, 0, *ciphertext + SALT_SIZE + IV_SIZE + TAG_SIZE, (ULONG)*ciphertext_len, &cbResult, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Encryption failed."));
        free(*ciphertext);
        *ciphertext = NULL;
        free(authInfo.pbTag);
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    *ciphertext_len = cbResult + SALT_SIZE + IV_SIZE + TAG_SIZE;

    // Prepend salt, IV, and tag to the ciphertext
    memcpy(*ciphertext, salt, SALT_SIZE);
    memcpy(*ciphertext + SALT_SIZE, iv, IV_SIZE);
    memcpy(*ciphertext + SALT_SIZE + IV_SIZE, authInfo.pbTag, TAG_SIZE);

    // Clean up
    free(authInfo.pbTag);
    BCryptDestroyKey(hKey);
    free(keyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Zero out key material
    SecureZeroMemory(key, KEY_SIZE);

    ret = 0;
    return ret;
}

// Function to decrypt data
int decrypt_data(unsigned char* ciphertext, size_t ciphertext_len, const TCHAR* password,
    unsigned char** plaintext, size_t* plaintext_len) {
    if (ciphertext_len < SALT_SIZE + IV_SIZE + TAG_SIZE) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    NTSTATUS status;
    int ret = -1;

    unsigned char* salt = ciphertext;
    unsigned char* iv = ciphertext + SALT_SIZE;
    unsigned char* tag = ciphertext + SALT_SIZE + IV_SIZE;
    unsigned char* enc_data = ciphertext + SALT_SIZE + IV_SIZE + TAG_SIZE;
    size_t enc_data_len = ciphertext_len - SALT_SIZE - IV_SIZE - TAG_SIZE;

    // Ensure enc_data_len is greater than zero
    if (enc_data_len == 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    // Derive key and IV
    unsigned char key[KEY_SIZE];
    unsigned char derived_iv[IV_SIZE];  // Not used in decryption
    if (derive_key_iv(password, salt, key, derived_iv) != 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    // Open algorithm provider
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    // Set chaining mode to GCM
    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Generate key object
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD keyObjectSize = 0;
    DWORD result = 0;
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &result, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    PUCHAR keyObject = (PUCHAR)malloc(keyObjectSize);
    if (keyObject == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectSize, key, KEY_SIZE, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Prepare the auth info structure
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = IV_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_SIZE;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    // Allocate plaintext buffer
    *plaintext_len = enc_data_len;
    *plaintext = (unsigned char*)malloc(*plaintext_len);
    if (*plaintext == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Declare cbResult before using it
    ULONG cbResult = 0;

    // Decrypt within a structured exception handler
    __try {
        if (!BCRYPT_SUCCESS(status = BCryptDecrypt(hKey, enc_data, (ULONG)enc_data_len, &authInfo, NULL, 0, *plaintext, (ULONG)*plaintext_len, &cbResult, 0))) {
            _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
            free(*plaintext);
            *plaintext = NULL;
            BCryptDestroyKey(hKey);
            free(keyObject);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return -1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        free(*plaintext);
        *plaintext = NULL;
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    *plaintext_len = cbResult;

    // Clean up
    BCryptDestroyKey(hKey);
    free(keyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Zero out key material
    SecureZeroMemory(key, KEY_SIZE);

    ret = 0;
    return ret;
}

// Function to derive key and IV
int derive_key_iv(const TCHAR* password, unsigned char* salt, unsigned char* key, unsigned char* iv) {
    int ret = -1;

#ifdef UNICODE
    int password_len = (int)_tcslen(password);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, password, password_len, NULL, 0, NULL, NULL);
    if (utf8_len <= 0) {
        return -1;
    }
    unsigned char* utf8_password = (unsigned char*)malloc(utf8_len);
    if (utf8_password == NULL) {
        return -1;
    }
    WideCharToMultiByte(CP_UTF8, 0, password, password_len, (LPSTR)utf8_password, utf8_len, NULL, NULL);
#else
    int utf8_len = (int)strlen(password);
    unsigned char* utf8_password = (unsigned char*)password;
#endif

    // Use PBKDF2-HMAC-SHA256 to derive key and IV
    unsigned char derived[KEY_SIZE + IV_SIZE];
    if (pbkdf2_hmac_sha256(utf8_password, utf8_len, salt, SALT_SIZE, 100000, derived, KEY_SIZE + IV_SIZE) != 0) {
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    memcpy(key, derived, KEY_SIZE);
    memcpy(iv, derived + KEY_SIZE, IV_SIZE);

#ifdef UNICODE
    SecureZeroMemory(utf8_password, utf8_len);
    free(utf8_password);
#endif

    ret = 0;
    return ret;
}

// PBKDF2-HMAC-SHA256 implementation
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
    const unsigned char* salt, size_t salt_len,
    unsigned int iterations, unsigned char* output, size_t output_len) {

    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, (ULONG)password_len, (PUCHAR)salt, (ULONG)salt_len, iterations, output, (ULONG)output_len, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}

// Function to generate HMAC
int generate_hmac(const TCHAR* password, unsigned char* data, size_t data_len, unsigned char* hmac_output) {
    NTSTATUS status;
    int ret = -1;

#ifdef UNICODE
    int password_len = (int)_tcslen(password);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, password, password_len, NULL, 0, NULL, NULL);
    if (utf8_len <= 0) {
        return -1;
    }
    unsigned char* utf8_password = (unsigned char*)malloc(utf8_len);
    if (utf8_password == NULL) {
        return -1;
    }
    WideCharToMultiByte(CP_UTF8, 0, password, password_len, (LPSTR)utf8_password, utf8_len, NULL, NULL);
#else
    int utf8_len = (int)strlen(password);
    unsigned char* utf8_password = (unsigned char*)password;
#endif

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    DWORD hashObjectSize = 0;
    DWORD result = 0;
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(DWORD), &result, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    PUCHAR hashObject = (PUCHAR)malloc(hashObjectSize);
    if (hashObject == NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, hashObject, hashObjectSize, utf8_password, utf8_len, 0))) {
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptHashData(hHash, data, (ULONG)data_len, 0))) {
        BCryptDestroyHash(hHash);
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptFinishHash(hHash, hmac_output, 32, 0))) {
        BCryptDestroyHash(hHash);
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    BCryptDestroyHash(hHash);
    free(hashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

#ifdef UNICODE
    SecureZeroMemory(utf8_password, utf8_len);
    free(utf8_password);
#endif

    ret = 0;
    return ret;
}
