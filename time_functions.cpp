#include "stdafx.h"
#include "time_functions.h"

void UnixTimeToFileTime(time_t t, LPFILETIME pft)
{
	// Note that LONGLONG is a 64-bit value
	LONGLONG ll;

	ll = Int32x32To64(t, 10000000) + 116444736000000000;
	pft->dwLowDateTime = (DWORD)ll;
	pft->dwHighDateTime = ll >> 32;
}

void UnixTimeToSystemTime(time_t t, LPSYSTEMTIME pst)
{
	FILETIME ft;

	UnixTimeToFileTime(t, &ft);
	FileTimeToSystemTime(&ft, pst);
}

INT VerifyLogonTimeToken(PWSTR ldap_timestamp)
{
	INT return_code = 0; // Default return value does not permit user to login;
	SYSTEMTIME st_now;
	FILETIME utc_now, utc_ldap;
	size_t timestamp_length;
	ULONGLONG timestamp_value;

	// Validate the length of timestamp, we expect POSIX format with at least 12 characters +1 for null termination;
	timestamp_length = wcsnlen_s(ldap_timestamp, 16);
	if (timestamp_length > 12) {
		timestamp_value = wcstoll(ldap_timestamp, NULL, 0);	// If base is 0, the initial characters of the string that's pointed to by strSource are used to determine the base;
		if (timestamp_value == ULLONG_MAX || timestamp_value == 0)	// Timestamp conversion failed due to incorrect value;
			return_code = -111;
		else {
			time_t ldap_time = timestamp_value;
			GetSystemTime(&st_now);
			SystemTimeToFileTime(&st_now, &utc_now);
			UnixTimeToFileTime(ldap_time, &utc_ldap);
			LONG ct = CompareFileTime(&utc_now, &utc_ldap);
			if (ct == -1)
				return_code = 1;	// Current UTC time is earlier that the UTC timestamp from the token, user can login;
		}
	}
	else
		return_code = -112;	// Timestamp value is incorrect;

	return return_code;
}