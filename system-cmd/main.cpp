

#include <windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <stdio.h>

void DisplayErrorMessage(LPTSTR pszMessage, DWORD dwLastError)
{
	HLOCAL hlErrorMessage = NULL;
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PTSTR)&hlErrorMessage, 0, NULL))
	{
		_tprintf(TEXT("%s: %s"), pszMessage, (PCTSTR)LocalLock(hlErrorMessage));
		LocalFree(hlErrorMessage);
	}
}

BOOL CurrentProcessAdjustToken(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES sTP;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}
	return FALSE;
}

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("[-]LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-]AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("[-]The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

void GetProcessUserName(HANDLE hProcess, char *pUser, DWORD size)
{
	HANDLE hToken;
	DWORD dwSize = 0;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		printf("[-]OpenProcessToken error : %d\n", GetLastError());
	}
	else
	{
		GetTokenInformation(hToken, TokenUser, NULL, dwSize, &dwSize);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			printf("[-]GetTokenInformation error : %d", GetLastError());
			return;
		}

		PTOKEN_USER pUserToken = (PTOKEN_USER)malloc(dwSize);

		if (0 != pUserToken)
		{
			if (GetTokenInformation(hToken, TokenUser, pUserToken, dwSize, &dwSize))
			{
				SID_NAME_USE   snuSIDNameUse;
				CHAR          szUser[MAX_PATH] = { 0 };
				DWORD          dwUserNameLength = MAX_PATH;
				CHAR          szDomain[MAX_PATH] = { 0 };
				DWORD          dwDomainNameLength = MAX_PATH;

				if (LookupAccountSid(NULL,
					pUserToken->User.Sid,
					szUser,
					&dwUserNameLength,
					szDomain,
					&dwDomainNameLength,
					&snuSIDNameUse))
				{
					printf("[*]Domain=%s User=%s\n", szDomain, szUser);
					strcpy_s(pUser, size, szUser);
				}
			}
			else
			{
				printf("[-]GetTokenInformation error : %d", GetLastError());
			}

			free(pUserToken);
		}

		CloseHandle(hToken);
	}

}

void GetProcessSessionID(HANDLE hProcess, DWORD *pSessionID)
{
	HANDLE hToken;
	DWORD dwSize = sizeof(DWORD);
	DWORD dwSessionID = 0;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		printf("[-]OpenProcessToken error : %d", GetLastError());
	}
	else
	{
		if (GetTokenInformation(hToken, TokenSessionId, &dwSessionID, dwSize, &dwSize))
		{
			printf("[*]SessionID=%d\n", dwSessionID);
			*pSessionID = dwSessionID;
		}
	}
}

void GetProcessOwner(HANDLE hProcess)
{
	HANDLE hToken;
	DWORD dwSize = 0;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		printf("[-]OpenProcessToken error : %d", GetLastError());
	}
	else
	{
		GetTokenInformation(hToken, TokenOwner, NULL, dwSize, &dwSize);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			printf("[-]GetTokenInformation error : %d", GetLastError());
			return;
		}

		PTOKEN_OWNER pUserToken = (PTOKEN_OWNER)malloc(dwSize);

		if (0 != pUserToken)
		{
			if (GetTokenInformation(hToken, TokenOwner, pUserToken, dwSize, &dwSize))
			{
				SID_NAME_USE   snuSIDNameUse;
				CHAR          szUser[MAX_PATH] = { 0 };
				DWORD          dwUserNameLength = MAX_PATH;
				CHAR          szDomain[MAX_PATH] = { 0 };
				DWORD          dwDomainNameLength = MAX_PATH;

				if (LookupAccountSid(NULL,
					pUserToken->Owner,
					szUser,
					&dwUserNameLength,
					szDomain,
					&dwDomainNameLength,
					&snuSIDNameUse))
				{
					printf("[*]Domain=%s User=%s\n", szDomain, szUser);
				}
			}
			else
			{
				printf("[-]GetTokenInformation error : %d", GetLastError());
			}

			free(pUserToken);
		}

		CloseHandle(hToken);
	}
}

DWORD GetSystemProcessID()
{
	DWORD ret = 0;

	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	BOOL bRet;

	HANDLE hCurrentToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrentToken))
	{
		bRet = SetPrivilege(hCurrentToken, SE_INCREASE_QUOTA_NAME, TRUE);
		bRet = SetPrivilege(hCurrentToken, SE_DEBUG_NAME, TRUE);
	}


	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		return -1;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("[-]Process32First error : %d", GetLastError()); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	do
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		if (0 == hProcess)
		{
			printf("[-]OpenProcess %d error : %d\n", pe32.th32ProcessID, GetLastError());
		}
		else
		{
			printf("[+]PID = %-4d    Image Name = %s\n", pe32.th32ProcessID, pe32.szExeFile);

			char szUser[128] = { 0 };
			DWORD sessionID;
			GetProcessUserName(hProcess, szUser, 128);
			//GetProcessOwner(hProcess);
			GetProcessSessionID(hProcess , &sessionID);
			
			if (_stricmp(szUser, "SYSTEM") == 0 && sessionID == 0)
			{ 
				ret = pe32.th32ProcessID;
				break;
			}


			CloseHandle(hProcess);
		}

	} while (Process32Next(hProcessSnap, &pe32));

	return ret;
}

int _tmain(int argc, _TCHAR* argv[])
{
	STARTUPINFOEX sie = { sizeof(sie) };
	PROCESS_INFORMATION pi;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;
	DWORD dwPid = 0;

	char cmd_path[MAX_PATH];
	char current_dir[MAX_PATH];
	GetSystemDirectory(cmd_path, MAX_PATH);
	GetSystemDirectory(current_dir, MAX_PATH);
	strcat_s(cmd_path, "\\cmd.exe");

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 14);

	_putts(TEXT("+-----------------------------------------+"));
	_putts(TEXT("+             SYSTEM-CMD v1.0             +"));
	_putts(TEXT("+-----------------------------------------+"));

	printf("[*]Searching process\n");

	dwPid = GetSystemProcessID();
	if (0 == dwPid)
	{
		_putts(TEXT("[-]Process Not Found"));
		return 0;
	}
	_putts(TEXT("[+]Process Found"));

	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	if (NULL == pAttributeList)
	{
		//DisplayErrorMessage(TEXT("HeapAlloc error"), GetLastError());
		return 0;
	}
	if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
	{
		//DisplayErrorMessage(TEXT("InitializeProcThreadAttributeList error"), GetLastError());
		return 0;
	}
	//CurrentProcessAdjustToken();
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hParentProcess)
	{
		//DisplayErrorMessage(TEXT("OpenProcess error"), GetLastError());
		return 0;
	}
	
	_putts(TEXT("[*]Update process attribute list\n"));

	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
	{
		//DisplayErrorMessage(TEXT("UpdateProcThreadAttribute error"), GetLastError());
		return 0;
	}
	sie.lpAttributeList = pAttributeList;

	if (!CreateProcess(NULL, cmd_path, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, current_dir, &sie.StartupInfo, &pi))
	{
		//DisplayErrorMessage(TEXT("CreateProcess error"), GetLastError());
		return 0;
	}
	//printf("Process created: %d\n", pi.dwProcessId);
	DeleteProcThreadAttributeList(pAttributeList);
	CloseHandle(hParentProcess);

	//WaitForSingleObject(pi.hProcess, INFINITE);


	return 0;
}