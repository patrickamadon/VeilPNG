// png_modifier.h

#ifndef PNG_MODIFIER_H
#define PNG_MODIFIER_H

#include <stddef.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	int make_first_pixel_transparent(unsigned char** png_data_ptr, size_t* png_size_ptr, TCHAR* error_message, size_t error_message_size);

#ifdef __cplusplus
}
#endif

#endif // PNG_MODIFIER_H
