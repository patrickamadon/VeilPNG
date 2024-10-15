// png_modifier.c

#define _CRT_SECURE_NO_WARNINGS
#include "png_modifier.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <stdint.h>
#include <tchar.h>
#include <winsock2.h>  // For ntohl and htonl functions
#include <windows.h>   // For SecureZeroMemory

// Ensure linking against Winsock library
#pragma comment(lib, "ws2_32.lib")

#define PNG_SIGNATURE_SIZE 8

// Internal function prototypes
static int parse_png_chunks(const unsigned char* png_data, size_t png_size,
    size_t* ihdr_pos, size_t* plte_pos, size_t* trns_pos, size_t* idat_pos,
    size_t* iend_pos, TCHAR* error_message, size_t error_message_size);
static int read_ihdr_chunk(const unsigned char* png_data, size_t ihdr_pos,
    uint32_t* width, uint32_t* height, uint8_t* bit_depth, uint8_t* color_type,
    TCHAR* error_message, size_t error_message_size);
static int make_first_pixel_transparent_indexed(unsigned char** png_data_ptr,
    size_t* png_size_ptr, TCHAR* error_message, size_t error_message_size);
static int make_first_pixel_transparent_truecolor(unsigned char** png_data_ptr,
    size_t* png_size_ptr, TCHAR* error_message, size_t error_message_size);

// Public function
int make_first_pixel_transparent(unsigned char** png_data_ptr, size_t* png_size_ptr,
    TCHAR* error_message, size_t error_message_size) {
    size_t ihdr_pos = 0;
    uint32_t width = 0, height = 0;
    uint8_t bit_depth = 0, color_type = 0;

    if (parse_png_chunks(*png_data_ptr, *png_size_ptr, &ihdr_pos, NULL, NULL,
        NULL, NULL, error_message, error_message_size) != 0) {
        return -1;
    }
    if (read_ihdr_chunk(*png_data_ptr, ihdr_pos, &width, &height, &bit_depth,
        &color_type, error_message, error_message_size) != 0) {
        return -1;
    }

    if (color_type == 3) {
        // Indexed color image
        if (make_first_pixel_transparent_indexed(png_data_ptr, png_size_ptr,
            error_message, error_message_size) != 0) {
            return -1;
        }
    }
    else if (color_type == 2 || color_type == 6) {
        // Truecolor or Truecolor with alpha
        if (make_first_pixel_transparent_truecolor(png_data_ptr, png_size_ptr,
            error_message, error_message_size) != 0) {
            return -1;
        }
    }
    else {
        _sntprintf_s(error_message, error_message_size, _TRUNCATE,
            _T("Unsupported color type: %d"), color_type);
        return -1;
    }

    return 0;
}

// Internal functions

static int parse_png_chunks(const unsigned char* png_data, size_t png_size,
    size_t* ihdr_pos, size_t* plte_pos, size_t* trns_pos, size_t* idat_pos,
    size_t* iend_pos, TCHAR* error_message, size_t error_message_size) {
    size_t pos = PNG_SIGNATURE_SIZE;  // Skip the PNG signature
    while (pos + 8 <= png_size) {
        // Read chunk length and type
        uint32_t chunk_length;
        memcpy(&chunk_length, png_data + pos, 4);
        chunk_length = ntohl(chunk_length);
        if (pos + 8 + chunk_length + 4 > png_size) {
            _tcscpy_s(error_message, error_message_size,
                _T("Invalid chunk length in PNG file."));
            return -1;
        }
        char chunk_type[5];
        memcpy(chunk_type, png_data + pos + 4, 4);
        chunk_type[4] = '\0';

        if (strcmp(chunk_type, "IHDR") == 0 && ihdr_pos) {
            *ihdr_pos = pos;
        }
        else if (strcmp(chunk_type, "PLTE") == 0 && plte_pos) {
            *plte_pos = pos;
        }
        else if (strcmp(chunk_type, "tRNS") == 0 && trns_pos) {
            *trns_pos = pos;
        }
        else if (strcmp(chunk_type, "IDAT") == 0 && idat_pos) {
            if (*idat_pos == 0)
                *idat_pos = pos;  // Record the position of the first IDAT chunk
        }
        else if (strcmp(chunk_type, "IEND") == 0 && iend_pos) {
            *iend_pos = pos;
            break;
        }

        pos += 8 + chunk_length + 4;  // Move to the next chunk
    }

    return 0;
}

static int read_ihdr_chunk(const unsigned char* png_data, size_t ihdr_pos,
    uint32_t* width, uint32_t* height, uint8_t* bit_depth, uint8_t* color_type,
    TCHAR* error_message, size_t error_message_size) {
    // IHDR chunk data starts after the 8-byte chunk header
    if (ihdr_pos + 8 + 13 > ihdr_pos + 8 + 13) {
        _tcscpy_s(error_message, error_message_size, _T("IHDR chunk is too small."));
        return -1;
    }
    const unsigned char* ihdr_data = png_data + ihdr_pos + 8;
    memcpy(width, ihdr_data, 4);
    *width = ntohl(*width);
    memcpy(height, ihdr_data + 4, 4);
    *height = ntohl(*height);
    *bit_depth = ihdr_data[8];
    *color_type = ihdr_data[9];

    return 0;
}

// Function to make the first pixel transparent in an indexed color image
static int make_first_pixel_transparent_indexed(unsigned char** png_data_ptr,
    size_t* png_size_ptr, TCHAR* error_message, size_t error_message_size) {
    // [Function implementation remains the same as your original code]
    // For brevity, the function is included in full below.

    size_t ihdr_pos = 0, plte_pos = 0, trns_pos = 0, idat_pos = 0, iend_pos = 0;
    if (parse_png_chunks(*png_data_ptr, *png_size_ptr, &ihdr_pos, &plte_pos, &trns_pos,
        &idat_pos, &iend_pos, error_message, error_message_size) != 0) {
        return -1;
    }

    if (plte_pos == 0) {
        _tcscpy_s(error_message, error_message_size, _T("PLTE chunk not found in indexed PNG image."));
        return -1;
    }

    unsigned char* png_data = *png_data_ptr;
    size_t png_size = *png_size_ptr;

    // Read PLTE chunk length
    uint32_t plte_length;
    memcpy(&plte_length, png_data + plte_pos, 4);
    plte_length = ntohl(plte_length);

    // Ensure PLTE length is a multiple of 3
    if (plte_length % 3 != 0) {
        _tcscpy_s(error_message, error_message_size, _T("Invalid PLTE chunk length."));
        return -1;
    }

    uint32_t num_palette_entries = plte_length / 3;

    // Create or modify tRNS chunk
    unsigned char* new_trns_chunk = NULL;
    size_t new_trns_chunk_size = 0;

    if (trns_pos == 0) {
        // tRNS chunk does not exist, create it
        new_trns_chunk_size = 8 + num_palette_entries + 4; // Length + Type + Data + CRC
        new_trns_chunk = (unsigned char*)malloc(new_trns_chunk_size);
        if (new_trns_chunk == NULL) {
            _tcscpy_s(error_message, error_message_size, _T("Memory allocation failed for tRNS chunk."));
            return -1;
        }

        uint32_t trns_length_be = htonl(num_palette_entries);
        memcpy(new_trns_chunk, &trns_length_be, 4); // Length
        memcpy(new_trns_chunk + 4, "tRNS", 4);      // Type

        // Set all alpha values to 0xFF (opaque)
        memset(new_trns_chunk + 8, 0xFF, num_palette_entries);

        // Set first palette entry to transparent
        new_trns_chunk[8] = 0x00;

        // Calculate CRC
        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, new_trns_chunk + 4, 4 + num_palette_entries);
        uint32_t crc_be = htonl(crc);
        memcpy(new_trns_chunk + 8 + num_palette_entries, &crc_be, 4);

        // Insert tRNS chunk after PLTE chunk
        size_t new_png_size = png_size + new_trns_chunk_size;
        unsigned char* new_png_data = (unsigned char*)malloc(new_png_size);
        if (new_png_data == NULL) {
            free(new_trns_chunk);
            _tcscpy_s(error_message, error_message_size, _T("Memory allocation failed for new PNG data."));
            return -1;
        }

        size_t plte_chunk_total_size = 8 + plte_length + 4;
        size_t before_trns_size = plte_pos + plte_chunk_total_size;
        size_t after_plte_size = png_size - before_trns_size;

        // Copy data before tRNS chunk
        memcpy(new_png_data, png_data, before_trns_size);

        // Insert tRNS chunk
        memcpy(new_png_data + before_trns_size, new_trns_chunk, new_trns_chunk_size);

        // Copy remaining data after PLTE chunk
        memcpy(new_png_data + before_trns_size + new_trns_chunk_size, png_data + before_trns_size, after_plte_size);

        free(new_trns_chunk);
        free(*png_data_ptr);
        *png_data_ptr = new_png_data;
        *png_size_ptr = new_png_size;

    }
    else {
        // tRNS chunk exists, modify it
        uint32_t trns_length;
        memcpy(&trns_length, png_data + trns_pos, 4);
        trns_length = ntohl(trns_length);

        if (trns_length < num_palette_entries) {
            // Need to expand tRNS chunk
            size_t new_trns_data_length = num_palette_entries;
            size_t new_trns_chunk_size = 8 + new_trns_data_length + 4;
            new_trns_chunk = (unsigned char*)malloc(new_trns_chunk_size);
            if (new_trns_chunk == NULL) {
                _tcscpy_s(error_message, error_message_size, _T("Memory allocation failed for new tRNS chunk."));
                return -1;
            }

            uint32_t trns_length_be = htonl(new_trns_data_length);
            memcpy(new_trns_chunk, &trns_length_be, 4); // Length
            memcpy(new_trns_chunk + 4, "tRNS", 4);      // Type

            // Copy existing tRNS data
            memcpy(new_trns_chunk + 8, png_data + trns_pos + 8, trns_length);

            // Set remaining alpha values to 0xFF
            memset(new_trns_chunk + 8 + trns_length, 0xFF, new_trns_data_length - trns_length);

            // Set first palette entry to transparent
            new_trns_chunk[8] = 0x00;

            // Calculate CRC
            uint32_t crc = crc32(0L, Z_NULL, 0);
            crc = crc32(crc, new_trns_chunk + 4, 4 + new_trns_data_length);
            uint32_t crc_be = htonl(crc);
            memcpy(new_trns_chunk + 8 + new_trns_data_length, &crc_be, 4);

            // Replace old tRNS chunk with new one
            size_t trns_chunk_total_size = 8 + trns_length + 4;
            size_t new_png_size = png_size - trns_chunk_total_size + new_trns_chunk_size;
            unsigned char* new_png_data = (unsigned char*)malloc(new_png_size);
            if (new_png_data == NULL) {
                free(new_trns_chunk);
                _tcscpy_s(error_message, error_message_size, _T("Memory allocation failed for new PNG data."));
                return -1;
            }

            // Copy data before tRNS chunk
            memcpy(new_png_data, png_data, trns_pos);

            // Insert new tRNS chunk
            memcpy(new_png_data + trns_pos, new_trns_chunk, new_trns_chunk_size);

            // Copy data after old tRNS chunk
            size_t after_trns_size = png_size - (trns_pos + trns_chunk_total_size);
            memcpy(new_png_data + trns_pos + new_trns_chunk_size, png_data + trns_pos + trns_chunk_total_size, after_trns_size);

            free(new_trns_chunk);
            free(*png_data_ptr);
            *png_data_ptr = new_png_data;
            *png_size_ptr = new_png_size;

        }
        else {
            // tRNS chunk has enough entries, modify it in place
            // Ensure we don't write beyond the allocated data
            if (trns_pos + 8 + num_palette_entries + 4 > png_size) {
                _tcscpy_s(error_message, error_message_size, _T("tRNS chunk size is inconsistent."));
                return -1;
            }

            // Set first palette entry to transparent
            png_data[trns_pos + 8] = 0x00;

            // Update CRC
            uint32_t crc = crc32(0L, Z_NULL, 0);
            crc = crc32(crc, png_data + trns_pos + 4, 4 + trns_length);
            uint32_t crc_be = htonl(crc);
            memcpy(png_data + trns_pos + 8 + trns_length, &crc_be, 4);
        }
    }

    return 0;
}

// Function to make the first pixel transparent in a truecolor image
static int make_first_pixel_transparent_truecolor(unsigned char** png_data_ptr,
    size_t* png_size_ptr, TCHAR* error_message, size_t error_message_size) {
    size_t ihdr_pos = 0, idat_pos = 0, iend_pos = 0;
    if (parse_png_chunks(*png_data_ptr, *png_size_ptr, &ihdr_pos, NULL, NULL,
        &idat_pos, &iend_pos, error_message, error_message_size) != 0) {
        return -1;
    }

    unsigned char* png_data = *png_data_ptr;
    size_t png_size = *png_size_ptr;

    uint32_t width = 0, height = 0;
    uint8_t bit_depth = 0, color_type = 0;
    if (read_ihdr_chunk(png_data, ihdr_pos, &width, &height, &bit_depth,
        &color_type, error_message, error_message_size) != 0) {
        return -1;
    }

    // Collect IDAT chunks
    size_t idat_total_length = 0;
    size_t pos = idat_pos;
    size_t idat_data_size = 0;
    while (pos + 8 <= png_size) {
        uint32_t chunk_length;
        memcpy(&chunk_length, png_data + pos, 4);
        chunk_length = ntohl(chunk_length);
        if (pos + 8 + chunk_length + 4 > png_size) {
            _tcscpy_s(error_message, error_message_size,
                _T("Invalid IDAT chunk length."));
            return -1;
        }
        char chunk_type[5];
        memcpy(chunk_type, png_data + pos + 4, 4);
        chunk_type[4] = '\0';

        if (strcmp(chunk_type, "IDAT") != 0) {
            break;
        }

        idat_total_length += 8 + chunk_length + 4; // Include chunk header and CRC
        idat_data_size += chunk_length;
        pos += 8 + chunk_length + 4;
    }

    // Ensure idat_data_size fits within uInt limit
    if (idat_data_size > UINT_MAX) {
        _tcscpy_s(error_message, error_message_size,
            _T("IDAT data size exceeds maximum allowable size."));
        return -1;
    }

    // Concatenate IDAT data
    unsigned char* idat_data = (unsigned char*)malloc(idat_data_size);
    if (!idat_data) {
        _tcscpy_s(error_message, error_message_size,
            _T("Memory allocation failed for IDAT data."));
        return -1;
    }

    size_t idat_data_offset = 0;
    pos = idat_pos;
    while (pos + 8 <= png_size) {
        uint32_t chunk_length;
        memcpy(&chunk_length, png_data + pos, 4);
        chunk_length = ntohl(chunk_length);
        if (pos + 8 + chunk_length + 4 > png_size) {
            free(idat_data);
            _tcscpy_s(error_message, error_message_size,
                _T("Invalid IDAT chunk length during concatenation."));
            return -1;
        }
        char chunk_type[5];
        memcpy(chunk_type, png_data + pos + 4, 4);
        chunk_type[4] = '\0';

        if (strcmp(chunk_type, "IDAT") != 0) {
            break;
        }

        memcpy(idat_data + idat_data_offset, png_data + pos + 8, chunk_length);
        idat_data_offset += chunk_length;
        pos += 8 + chunk_length + 4;
    }

    // Decompress image data
    size_t channels = (color_type == 6) ? 4 : 3;
    size_t bytes_per_pixel = (bit_depth / 8) * channels;
    size_t bytes_per_row = bytes_per_pixel * width + 1;  // +1 for filter byte

    // Calculate image_data_size safely
    size_t image_data_size = bytes_per_row * height;
    if (bytes_per_row != 0 && image_data_size / bytes_per_row != height) {
        _tcscpy_s(error_message, error_message_size,
            _T("Integer overflow in image size calculation."));
        free(idat_data);
        return -1;
    }

    // Ensure image_data_size fits within uInt limit
    if (image_data_size > UINT_MAX) {
        _tcscpy_s(error_message, error_message_size,
            _T("Image data size exceeds maximum allowable size."));
        free(idat_data);
        return -1;
    }

    unsigned char* image_data = (unsigned char*)malloc(image_data_size);
    if (!image_data) {
        _tcscpy_s(error_message, error_message_size,
            _T("Memory allocation failed for image data."));
        free(idat_data);
        return -1;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = idat_data;

    // Check idat_data_size fits into uInt
    if (idat_data_size > UINT_MAX) {
        _tcscpy_s(error_message, error_message_size,
            _T("IDAT data size exceeds maximum allowable size."));
        free(image_data);
        free(idat_data);
        return -1;
    }
    strm.avail_in = (uInt)idat_data_size;

    strm.next_out = image_data;
    // Check image_data_size fits into uInt
    if (image_data_size > UINT_MAX) {
        _tcscpy_s(error_message, error_message_size,
            _T("Image data size exceeds maximum allowable size."));
        free(image_data);
        free(idat_data);
        return -1;
    }
    strm.avail_out = (uInt)image_data_size;

    // Initialize zlib for PNG decompression
    if (inflateInit(&strm) != Z_OK) {
        _tcscpy_s(error_message, error_message_size,
            _T("Failed to initialize zlib inflate."));
        free(image_data);
        free(idat_data);
        return -1;
    }

    int ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&strm);
        const char* zlib_error = strm.msg ? strm.msg : zError(ret);
        _sntprintf_s(error_message, error_message_size, _TRUNCATE,
            _T("Failed to decompress image data: %S"), zlib_error);
        free(image_data);
        free(idat_data);
        return -1;
    }
    inflateEnd(&strm);

    free(idat_data);

    // Modify the first pixel's alpha value
    size_t pos_pixel = 1;  // Skip filter byte for the first row

    // Ensure we don't write beyond image_data
    if (pos_pixel + bytes_per_pixel > image_data_size) {
        _tcscpy_s(error_message, error_message_size, _T("Buffer overflow in image_data."));
        free(image_data);
        return -1;
    }

    if (color_type == 6) {
        // RGBA
        image_data[pos_pixel + 3] = 0x00;  // Set alpha to zero
    }
    else if (color_type == 2) {
        // RGB -> Need to add an alpha channel
        // Expand image data to include alpha channel
        size_t new_image_data_size = (width * 4 + 1) * height;  // +1 filter byte per row

        // Check for potential overflow
        if (width > (SIZE_MAX - 1) / 4 || new_image_data_size / height != width * 4 + 1) {
            _tcscpy_s(error_message, error_message_size,
                _T("Integer overflow in new image size calculation."));
            free(image_data);
            return -1;
        }

        unsigned char* new_image_data = (unsigned char*)malloc(new_image_data_size);
        if (!new_image_data) {
            _tcscpy_s(error_message, error_message_size,
                _T("Memory allocation failed for new image data."));
            free(image_data);
            return -1;
        }

        size_t src_offset = 0;
        size_t dst_offset = 0;
        for (uint32_t y = 0; y < height; y++) {
            if (dst_offset + 1 > new_image_data_size || src_offset + 1 > image_data_size) {
                free(image_data);
                free(new_image_data);
                _tcscpy_s(error_message, error_message_size, _T("Buffer overflow in new_image_data."));
                return -1;
            }
            new_image_data[dst_offset++] = image_data[src_offset++]; // Copy filter byte

            for (uint32_t x = 0; x < width; x++) {
                if (dst_offset + 4 > new_image_data_size || src_offset + 3 > image_data_size) {
                    free(image_data);
                    free(new_image_data);
                    _tcscpy_s(error_message, error_message_size, _T("Buffer overflow in new_image_data or image_data."));
                    return -1;
                }
                new_image_data[dst_offset++] = image_data[src_offset++]; // R
                new_image_data[dst_offset++] = image_data[src_offset++]; // G
                new_image_data[dst_offset++] = image_data[src_offset++]; // B
                new_image_data[dst_offset++] = 0xFF;                     // Alpha
            }
        }

        free(image_data);
        image_data = new_image_data;
        image_data_size = new_image_data_size;

        // Update color type to 6 (RGBA)
        png_data[ihdr_pos + 8 + 9] = 6;

        // Recalculate IHDR CRC
        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, png_data + ihdr_pos + 4, 4 + 13);  // "IHDR" + 13 bytes of data
        uint32_t crc_be = htonl(crc);
        memcpy(png_data + ihdr_pos + 8 + 13, &crc_be, 4);

        // Now modify the first pixel's alpha value
        image_data[pos_pixel + 3] = 0x00;  // Set alpha to zero
    }
    else {
        _sntprintf_s(error_message, error_message_size, _TRUNCATE,
            _T("Unsupported color type for alpha modification: %d"), color_type);
        free(image_data);
        return -1;
    }

    // Recompress image data
    // Ensure image_data_size fits into uLong
    if (image_data_size > ULONG_MAX) {
        _tcscpy_s(error_message, error_message_size,
            _T("Image data size exceeds maximum allowable size for compression."));
        free(image_data);
        return -1;
    }

    uLongf compressed_size_ul = compressBound((uLong)image_data_size);
    size_t compressed_size = (size_t)compressed_size_ul;

    unsigned char* compressed_data = (unsigned char*)malloc(compressed_size);
    if (!compressed_data) {
        _tcscpy_s(error_message, error_message_size,
            _T("Memory allocation failed for compressed data."));
        free(image_data);
        return -1;
    }

    // Ensure image_data_size fits into uLong before casting
    if (image_data_size > ULONG_MAX) {
        _tcscpy_s(error_message, error_message_size,
            _T("Image data size exceeds maximum allowable size for compression."));
        free(image_data);
        free(compressed_data);
        return -1;
    }

    int z_result = compress2(compressed_data, &compressed_size_ul, image_data,
        (uLong)image_data_size, Z_BEST_COMPRESSION);
    compressed_size = (size_t)compressed_size_ul;

    if (z_result != Z_OK) {
        _tcscpy_s(error_message, error_message_size,
            _T("Image data compression failed."));
        free(image_data);
        free(compressed_data);
        return -1;
    }

    free(image_data);

    // Replace IDAT chunks
    size_t new_png_size = png_size - idat_total_length + (8 + compressed_size + 4);
    unsigned char* new_png_data = (unsigned char*)malloc(new_png_size);
    if (!new_png_data) {
        _tcscpy_s(error_message, error_message_size,
            _T("Memory allocation failed for new PNG data."));
        free(compressed_data);
        return -1;
    }

    // Copy data before IDAT chunks
    memcpy(new_png_data, png_data, idat_pos);

    // Prepare new IDAT chunk
    uint32_t idat_length_be = htonl((uint32_t)compressed_size);
    memcpy(new_png_data + idat_pos, &idat_length_be, 4);
    memcpy(new_png_data + idat_pos + 4, "IDAT", 4);
    memcpy(new_png_data + idat_pos + 8, compressed_data, compressed_size);

    // Calculate CRC for IDAT chunk
    uint32_t crc = crc32(0L, Z_NULL, 0);
    if (compressed_size > UINT_MAX) {
        _tcscpy_s(error_message, error_message_size, _T("Compressed data size exceeds maximum allowable size."));
        free(new_png_data);
        free(compressed_data);
        return -1;
    }
    crc = crc32(crc, new_png_data + idat_pos + 4, 4 + (uInt)compressed_size);
    uint32_t crc_be = htonl(crc);
    memcpy(new_png_data + idat_pos + 8 + compressed_size, &crc_be, 4);

    // Copy remaining data after old IDAT chunks
    size_t remaining_data_size = png_size - (idat_pos + idat_total_length);
    memcpy(new_png_data + idat_pos + 8 + compressed_size + 4,
        png_data + idat_pos + idat_total_length, remaining_data_size);

    free(*png_data_ptr);
    free(compressed_data);
    *png_data_ptr = new_png_data;
    *png_size_ptr = new_png_size;

    return 0;
}
