#ifndef sveil_EMBED_H
#define sveil_EMBED_H

#include <windows.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	int sveil_embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password);

#ifdef __cplusplus
}
#endif

#endif // sveil_EMBED_H
