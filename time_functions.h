#pragma once
#ifndef TIME_F
#define TIME_F

#include <windows.h>
#include <time.h>
#include <wchar.h>
#include <limits.h>

void UnixTimeToFileTime(time_t, LPFILETIME);
void UnixTimeToSystemTime(time_t, LPSYSTEMTIME);
INT VerifyLogonTimeToken(PWSTR);

#endif //TIME_F