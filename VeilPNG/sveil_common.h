// sveil_common.h

#ifndef sveil_COMMON_H
#define sveil_COMMON_H

#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	void set_sveil_error_message(const TCHAR* format, ...);
	const TCHAR* get_sveil_error_message(void);
	void secure_zero_memory(void* ptr, size_t cnt);

#ifdef __cplusplus
}
#endif

#endif // sveil_COMMON_H
