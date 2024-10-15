// png_handler.c

#define _CRT_SECURE_NO_WARNINGS
#include "png_handler.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <tchar.h>
#include <stdio.h>  // Include for file I/O functions

#define PNG_SIG_SIZE 8
#define CHUNK_HEADER_SIZE 8
#define CHUNK_CRC_SIZE 4

// Static buffer to hold error messages
static TCHAR png_handler_error_message[512];

const TCHAR* get_png_handler_error_message() {
    return png_handler_error_message;
}

// Function to convert 32-bit integer from host byte order to big-endian
unsigned int to_big_endian(unsigned int val) {
    return ((val & 0xFF) << 24) |
        ((val & 0xFF00) << 8) |
        ((val & 0xFF0000) >> 8) |
        ((val & 0xFF000000) >> 24);
}

// Function to convert 32-bit integer from big-endian to host byte order
unsigned int from_big_endian(unsigned int val) {
    return to_big_endian(val); // Since to_big_endian is reversible
}

int read_file(const TCHAR* path, unsigned char** data, size_t* size) {
    FILE* fp = _tfopen(path, _T("rb"));
    if (!fp) {
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Failed to open file."));
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Failed to determine file size."));
        return -1;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Failed to determine file size."));
        return -1;
    }
    *size = (size_t)file_size;
    rewind(fp);

    *data = (unsigned char*)malloc(*size);
    if (*data == NULL) {
        fclose(fp);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Memory allocation failed."));
        return -1;
    }

    if (fread(*data, 1, *size, fp) != *size) {
        fclose(fp);
        free(*data);
        *data = NULL;
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Failed to read file data."));
        return -1;
    }
    fclose(fp);
    return 0;
}

int write_file(const TCHAR* path, unsigned char* data, size_t size) {
    FILE* fp = _tfopen(path, _T("wb"));
    if (!fp) {
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Failed to open file for writing."));
        return -1;
    }

    if (fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Failed to write data to file."));
        return -1;
    }
    fclose(fp);
    return 0;
}

unsigned long calculate_crc(unsigned char* data, size_t length) {
    return crc32(0L, data, (uInt)length);
}

int insert_custom_chunk(unsigned char* png_data, size_t png_size, unsigned char* chunk_data, size_t chunk_size,
    const char* chunk_type, unsigned char** out_png_data, size_t* out_png_size) {
    // Find the location to insert the custom chunk (before IEND)
    size_t offset = PNG_SIG_SIZE;
    size_t insert_pos = 0;
    while (offset + CHUNK_HEADER_SIZE <= png_size) {
        unsigned int length_be;
        memcpy(&length_be, png_data + offset, 4);
        unsigned int length = from_big_endian(length_be);
        if (offset + CHUNK_HEADER_SIZE + length + CHUNK_CRC_SIZE > png_size) {
            break;
        }
        char type[5];
        memcpy(type, &png_data[offset + 4], 4);
        type[4] = '\0';

        if (strcmp(type, "IEND") == 0) {
            insert_pos = offset;
            break;
        }
        offset += CHUNK_HEADER_SIZE + length + CHUNK_CRC_SIZE;
    }

    if (insert_pos == 0) {
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("IEND chunk not found."));
        return -1;
    }

    // Build the custom chunk
    size_t new_chunk_size = CHUNK_HEADER_SIZE + chunk_size + CHUNK_CRC_SIZE;
    unsigned char* new_chunk = (unsigned char*)malloc(new_chunk_size);
    if (new_chunk == NULL) {
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Memory allocation failed."));
        return -1;
    }

    // Initialize variables to keep track of positions
    size_t new_chunk_offset = 0;

    // Chunk Length
    if (new_chunk_offset + 4 > new_chunk_size) {
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow in new_chunk."));
        return -1;
    }
    unsigned int chunk_length_be = to_big_endian((unsigned int)chunk_size);
    memcpy(new_chunk + new_chunk_offset, &chunk_length_be, 4);
    new_chunk_offset += 4;

    // Chunk Type
    if (new_chunk_offset + 4 > new_chunk_size) {
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow in new_chunk."));
        return -1;
    }
    memcpy(new_chunk + new_chunk_offset, chunk_type, 4);
    new_chunk_offset += 4;

    // Chunk Data
    if (new_chunk_offset + chunk_size > new_chunk_size) {
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow in new_chunk."));
        return -1;
    }
    memcpy(new_chunk + new_chunk_offset, chunk_data, chunk_size);
    new_chunk_offset += chunk_size;

    // Chunk CRC
    if (new_chunk_offset + 4 > new_chunk_size) {
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow in new_chunk."));
        return -1;
    }
    unsigned long crc = calculate_crc(new_chunk + 4, 4 + chunk_size); // Type + Data
    unsigned int crc_be = to_big_endian((unsigned int)crc);
    memcpy(new_chunk + new_chunk_offset, &crc_be, 4);
    new_chunk_offset += 4;

    // Create new PNG data
    *out_png_size = png_size + new_chunk_size;
    *out_png_data = (unsigned char*)malloc(*out_png_size);
    if (*out_png_data == NULL) {
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Memory allocation failed."));
        free(new_chunk);
        return -1;
    }

    // Copy data up to insertion point
    size_t copy_offset = 0;
    if (copy_offset + insert_pos > *out_png_size) {
        free(*out_png_data);
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow in out_png_data."));
        return -1;
    }
    memcpy(*out_png_data + copy_offset, png_data, insert_pos);
    copy_offset += insert_pos;

    // Insert custom chunk
    if (copy_offset + new_chunk_size > *out_png_size) {
        free(*out_png_data);
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow when inserting new chunk."));
        return -1;
    }
    memcpy(*out_png_data + copy_offset, new_chunk, new_chunk_size);
    copy_offset += new_chunk_size;

    // Copy remaining data (IEND chunk and any data after)
    size_t remaining_data_size = png_size - insert_pos;
    if (copy_offset + remaining_data_size > *out_png_size) {
        free(*out_png_data);
        free(new_chunk);
        _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Buffer overflow when copying remaining data."));
        return -1;
    }
    memcpy(*out_png_data + copy_offset, png_data + insert_pos, remaining_data_size);
    copy_offset += remaining_data_size;

    free(new_chunk);
    return 0;
}

int extract_custom_chunk(unsigned char* png_data, size_t png_size, const char* chunk_type,
    unsigned char** chunk_data, size_t* chunk_size) {
    size_t offset = PNG_SIG_SIZE;
    while (offset + CHUNK_HEADER_SIZE <= png_size) {
        unsigned int length_be;
        memcpy(&length_be, png_data + offset, 4);
        unsigned int length = from_big_endian(length_be);
        if (offset + CHUNK_HEADER_SIZE + length + CHUNK_CRC_SIZE > png_size) {
            break;
        }
        char type[5];
        memcpy(type, &png_data[offset + 4], 4);
        type[4] = '\0';

        if (strcmp(type, chunk_type) == 0) {
            // Found the custom chunk
            *chunk_size = length;
            *chunk_data = (unsigned char*)malloc(length);
            if (*chunk_data == NULL) {
                _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Memory allocation failed."));
                return -1;
            }
            memcpy(*chunk_data, &png_data[offset + CHUNK_HEADER_SIZE], length);
            return 0;
        }
        offset += CHUNK_HEADER_SIZE + length + CHUNK_CRC_SIZE;
    }

    _tcscpy_s(png_handler_error_message, _countof(png_handler_error_message), _T("Custom chunk not found."));
    return -1;
}
