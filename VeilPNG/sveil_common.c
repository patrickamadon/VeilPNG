// sveil_common.c

#define _CRT_SECURE_NO_WARNINGS

#include "sveil_common.h"
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>  // For SecureZeroMemory
#include <tchar.h>

#define ERROR_MESSAGE_BUFFER_SIZE 512
static TCHAR error_message[ERROR_MESSAGE_BUFFER_SIZE];

void set_sveil_error_message(const TCHAR* format, ...) {
    va_list args;
    va_start(args, format);
    _vsntprintf_s(error_message, ERROR_MESSAGE_BUFFER_SIZE, _TRUNCATE, format, args);
    va_end(args);
}

const TCHAR* get_sveil_error_message(void) {
    return error_message;
}

void secure_zero_memory(void* ptr, size_t cnt) {
    SecureZeroMemory(ptr, cnt);
}
