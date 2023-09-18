// C Libraries
#include <string.h>

// WinAPI Libraries
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#ifdef UNICODE
#define LOAD_LIBRARY_PROCNAME "LoadLibraryW"
#else
#define LOAD_LIBRARY_PROCNAME "LoadLibraryA"
#endif

DWORD GetPIDByName(LPCTSTR lpszProcessName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 
    if(Process32First(snapshot, &entry))
        while(Process32Next(snapshot, &entry))
            if(!_tcsicmp(entry.szExeFile, lpszProcessName))
			{
				CloseHandle(snapshot);
                return entry.th32ProcessID;
			};
 
    return 0;
}

int _tmain(int argc,LPTSTR argv[])
{
	TCHAR lpszDllNameBuffer[MAX_PATH];

	LPCTSTR lpszProcessName = argv[1], lpszDllName = argv[2];

	for(int i = 1;i < argc;i++)
	{
		if(!_tcsicmp(argv[i],TEXT("-process")) || !_tcsicmp(argv[i],TEXT("-proc")) || !_tcsicmp(argv[i],TEXT("-procname")))
			lpszProcessName = argv[++i];

		if(!_tcsicmp(argv[i],TEXT("-dll")) || !_tcsicmp(argv[i],TEXT("-library")))
			lpszDllName = argv[++i];
	}
	
	if(PathIsRelative(lpszDllName))
	{
		DWORD dwResult = SearchPath(NULL,lpszDllName,NULL,MAX_PATH,lpszDllNameBuffer,NULL);
		lpszDllName = lpszDllNameBuffer;

		if (!dwResult)
		{
			DWORD dwError = GetLastError();

			LPTSTR lpBuffer = NULL;

			FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpBuffer, 0, NULL);

			_tprintf(TEXT("Failed to find dll: [%lu] %s\n"),dwError,lpBuffer);

			return EXIT_FAILURE;
		}
	}

	DWORD dwPid = GetPIDByName(lpszProcessName);

	if(dwPid == 0)
	{
		_tprintf(TEXT("Failed to get process id (%s)\n"),lpszProcessName);

		return EXIT_FAILURE;
	}
	
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPid);

	if (hProcess == NULL)
	{
		_tprintf(TEXT("Failed to get process handle\n"));

		return EXIT_FAILURE;
	}

	size_t uSize = (SIZE_T)((_tcsclen(lpszDllName) + 1) * sizeof(TCHAR));
	
	LPVOID lpMemory = VirtualAllocEx(hProcess,NULL,uSize,MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	if (lpMemory == NULL)
	{
		_tprintf(TEXT("Failed to allocate memory\n"));

		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	if (!WriteProcessMemory(hProcess,lpMemory,(LPCVOID)(lpszDllName),uSize,0u))
	{
		DWORD dwError = GetLastError();

		LPTSTR lpBuffer = NULL;

		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpBuffer, 0, NULL);

		_tprintf(TEXT("Failed to write memory: [%lu] %s\n"),dwError,lpBuffer);

		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	HANDLE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));

	if(hKernel32 == NULL)
	{
		_tprintf(TEXT("Failed to get Kernel32.dll module handle\n"));

		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	LPTHREAD_START_ROUTINE lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32,LOAD_LIBRARY_PROCNAME);

	if(lpLoadLibrary == NULL)
	{
		_tprintf(TEXT("Failed to get %s entry inside Kernel32.dll\n"),TEXT(LOAD_LIBRARY_PROCNAME));

		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	HANDLE hThread = CreateRemoteThread(hProcess,NULL,0u,lpLoadLibrary,lpMemory,0,NULL);

	if (hThread == NULL)
	{
		DWORD dwError = GetLastError();

		LPTSTR lpBuffer = NULL;

		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpBuffer, 0, NULL);

		_tprintf(TEXT("Failed to create remote thread: [%lu] %s\n"),dwError,lpBuffer);

		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	WaitForSingleObject(hThread, INFINITE);

	DWORD dwExitCode;

	if (!GetExitCodeThread(hThread,&dwExitCode))
	{
		_tprintf(TEXT("Failed to get thread exit code"));
		
		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	if(!dwExitCode)
	{
		_tprintf(TEXT("Failed to call %s in remote process %s"),TEXT(LOAD_LIBRARY_PROCNAME),lpszProcessName);
		
		CloseHandle(hProcess);

		return EXIT_FAILURE;
	}

	_tprintf(TEXT("Successfully injected \"%s\" into process [%lu] %s\n"),lpszDllName,dwPid,lpszProcessName);

	return EXIT_SUCCESS;
}