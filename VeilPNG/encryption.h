// encryption.h

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <tchar.h>
#include <stddef.h>

int encrypt_data(unsigned char* plaintext, size_t plaintext_len, const TCHAR* password,
    unsigned char** ciphertext, size_t* ciphertext_len);
int decrypt_data(unsigned char* ciphertext, size_t ciphertext_len, const TCHAR* password,
    unsigned char** plaintext, size_t* plaintext_len);
int generate_hmac(const TCHAR* password, unsigned char* data, size_t data_len, unsigned char* hmac_output);

// Add this line:
const TCHAR* get_encryption_error_message();

#endif // ENCRYPTION_H
