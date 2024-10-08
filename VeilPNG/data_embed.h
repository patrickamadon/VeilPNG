// data_embed.h

#ifndef DATA_EMBED_H
#define DATA_EMBED_H

#include <tchar.h>

int embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password);
int extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password, TCHAR* extracted_file_name);

// Add this line:
const TCHAR* get_last_error_message();

#endif // DATA_EMBED_H

