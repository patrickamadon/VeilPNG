// sveil_png_utils.h

#ifndef sveil_PNG_UTILS_H
#define sveil_PNG_UTILS_H

#include <stddef.h>
#include <stdint.h>

// Function to collect IDAT chunks from a PNG file
int collect_idat_chunks(const unsigned char* png_data, size_t png_size,
    unsigned char** idat_data_out, size_t* idat_size_out,
    size_t* idat_pos_out, size_t* idat_total_length_out);

// Function to replace IDAT chunks in a PNG file
int replace_idat_chunks(unsigned char** png_data_ptr, size_t* png_size_ptr,
    size_t idat_pos, size_t idat_total_length,
    const unsigned char* new_idat_data, size_t new_idat_size);

// Function to decompress IDAT data
int uncompress_idat_data(const unsigned char* compressed_data, size_t compressed_size,
    unsigned char** image_data_out, size_t* image_data_size_out);

#endif // sveil_PNG_UTILS_H
