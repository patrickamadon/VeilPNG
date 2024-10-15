// sveil_extract.h

#ifndef sveil_EXTRACT_H
#define sveil_EXTRACT_H

#include <windows.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	int sveil_extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password, TCHAR* extracted_file_name);

#ifdef __cplusplus
}
#endif

#endif // sveil_EXTRACT_H
