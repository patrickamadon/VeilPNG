// sveil_png_utils.c

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <zlib.h>
#pragma comment(lib, "zlibstat.lib")

#include "sveil_png_utils.h"
#include "sveil_common.h"

#define CHUNK_HEADER_SIZE 8  // Length (4 bytes) + Type (4 bytes)
#define CHUNK_CRC_SIZE 4

// Function to collect IDAT chunks from a PNG file
int collect_idat_chunks(const unsigned char* png_data, size_t png_size,
    unsigned char** idat_data_out, size_t* idat_size_out,
    size_t* idat_pos_out, size_t* idat_total_length_out) {
    size_t pos = 8; // Skip PNG signature
    size_t idat_size = 0;
    size_t idat_pos = 0;
    size_t idat_total_length = 0;
    unsigned char* idat_data = NULL;

    while (pos + CHUNK_HEADER_SIZE + CHUNK_CRC_SIZE <= png_size) {
        if (pos + 8 > png_size) break;
        uint32_t chunk_length = ntohl(*(uint32_t*)(png_data + pos));
        if (pos + CHUNK_HEADER_SIZE + chunk_length + CHUNK_CRC_SIZE > png_size) break;

        char chunk_type[5] = { 0 };
        memcpy(chunk_type, png_data + pos + 4, 4);

        if (memcmp(chunk_type, "IDAT", 4) == 0) {
            if (idat_pos == 0) {
                idat_pos = pos;
            }
            idat_total_length += CHUNK_HEADER_SIZE + chunk_length + CHUNK_CRC_SIZE;

            unsigned char* temp = (unsigned char*)realloc(idat_data, idat_size + chunk_length);
            if (!temp) {
                if (idat_data) free(idat_data);
                set_sveil_error_message(_T("Memory allocation failed for IDAT data."));
                return -1;
            }
            idat_data = temp;

            memcpy(idat_data + idat_size, png_data + pos + CHUNK_HEADER_SIZE, chunk_length);
            idat_size += chunk_length;
        }

        pos += CHUNK_HEADER_SIZE + chunk_length + CHUNK_CRC_SIZE;
    }

    if (idat_size == 0) {
        set_sveil_error_message(_T("No IDAT chunks found."));
        return -1;
    }

    if (idat_data_out) {
        *idat_data_out = idat_data;
    }
    else {
        free(idat_data);
    }
    if (idat_size_out) {
        *idat_size_out = idat_size;
    }
    if (idat_pos_out) {
        *idat_pos_out = idat_pos;
    }
    if (idat_total_length_out) {
        *idat_total_length_out = idat_total_length;
    }

    return 0;
}

// Function to replace IDAT chunks in a PNG file
int replace_idat_chunks(unsigned char** png_data_ptr, size_t* png_size_ptr,
    size_t idat_pos, size_t idat_total_length,
    const unsigned char* new_idat_data, size_t new_idat_size) {
    unsigned char* png_data = *png_data_ptr;
    size_t png_size = *png_size_ptr;

    // Remove existing IDAT chunks
    memmove(png_data + idat_pos, png_data + idat_pos + idat_total_length, png_size - idat_pos - idat_total_length);
    png_size -= idat_total_length;

    // Create new IDAT chunk
    size_t new_chunk_size = CHUNK_HEADER_SIZE + new_idat_size + CHUNK_CRC_SIZE;
    unsigned char* new_png_data = (unsigned char*)malloc(png_size + new_chunk_size);
    if (!new_png_data) {
        set_sveil_error_message(_T("Memory allocation failed for new PNG data."));
        return -1;
    }

    // Copy data before IDAT
    memcpy(new_png_data, png_data, idat_pos);

    // Write new IDAT chunk
    uint32_t length_be = htonl((uint32_t)new_idat_size);
    memcpy(new_png_data + idat_pos, &length_be, 4);
    memcpy(new_png_data + idat_pos + 4, "IDAT", 4);
    memcpy(new_png_data + idat_pos + 8, new_idat_data, new_idat_size);

    // Calculate CRC
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef*)(new_png_data + idat_pos + 4), (uInt)(new_idat_size + 4));
    uint32_t crc_be = htonl((uint32_t)crc);
    memcpy(new_png_data + idat_pos + 8 + new_idat_size, &crc_be, 4);

    // Copy data after IDAT
    memcpy(new_png_data + idat_pos + new_chunk_size, png_data + idat_pos, png_size - idat_pos);

    // Update png_data and png_size
    free(*png_data_ptr);
    *png_data_ptr = new_png_data;
    *png_size_ptr = png_size + new_chunk_size;

    return 0;
}

// Function to decompress IDAT data
int uncompress_idat_data(const unsigned char* compressed_data, size_t compressed_size,
    unsigned char** image_data_out, size_t* image_data_size_out) {
    size_t image_data_alloc_size = compressed_size * 10;  // Estimate
    unsigned char* image_data = (unsigned char*)malloc(image_data_alloc_size);
    if (!image_data) {
        set_sveil_error_message(_T("Memory allocation failed for image data."));
        return -1;
    }

    z_stream strm = { 0 };
    strm.next_in = (unsigned char*)compressed_data;
    strm.avail_in = (uInt)compressed_size;
    strm.next_out = image_data;
    strm.avail_out = (uInt)image_data_alloc_size;

    if (inflateInit(&strm) != Z_OK) {
        set_sveil_error_message(_T("inflateInit failed."));
        free(image_data);
        return -1;
    }

    int ret = inflate(&strm, Z_NO_FLUSH);
    while (ret == Z_OK) {
        if (strm.avail_out == 0) {
            image_data_alloc_size *= 2;
            unsigned char* temp = (unsigned char*)realloc(image_data, image_data_alloc_size);
            if (!temp) {
                set_sveil_error_message(_T("Memory allocation failed during decompression."));
                free(image_data);
                inflateEnd(&strm);
                return -1;
            }
            image_data = temp;
            strm.next_out = image_data + strm.total_out;
            strm.avail_out = (uInt)(image_data_alloc_size - strm.total_out);
        }
        ret = inflate(&strm, Z_NO_FLUSH);
    }

    if (ret != Z_STREAM_END) {
        set_sveil_error_message(_T("Failed to decompress IDAT data."));
        free(image_data);
        inflateEnd(&strm);
        return -1;
    }

    *image_data_size_out = strm.total_out;
    *image_data_out = image_data;

    inflateEnd(&strm);
    return 0;
}
