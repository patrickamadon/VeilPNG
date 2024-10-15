// png_handler.h

#ifndef PNG_HANDLER_H
#define PNG_HANDLER_H

#include <tchar.h>

// Function prototypes
int read_file(const TCHAR* path, unsigned char** data, size_t* size);
int write_file(const TCHAR* path, unsigned char* data, size_t size);
unsigned long calculate_crc(unsigned char* data, size_t length);
int insert_custom_chunk(unsigned char* png_data, size_t png_size, unsigned char* chunk_data, size_t chunk_size,
    const char* chunk_type, unsigned char** out_png_data, size_t* out_png_size);
int extract_custom_chunk(unsigned char* png_data, size_t png_size, const char* chunk_type,
    unsigned char** chunk_data, size_t* chunk_size);

// Function to get the last error message
const TCHAR* get_png_handler_error_message();

#endif // PNG_HANDLER_H
