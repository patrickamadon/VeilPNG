#ifndef sveil_STEGANOGRAPHY_H
#define sveil_STEGANOGRAPHY_H

#include <windows.h>
#include <tchar.h>

int sveil_embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password);
int sveil_extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password, TCHAR* extracted_file_name);
const TCHAR* get_sveil_error_message();

#endif // sveil_STEGANOGRAPHY_H
