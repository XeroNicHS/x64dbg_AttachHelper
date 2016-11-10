//-------------------------------------------------------------------
//   Attach Helper [ x64dbg plugin ]
//
//   @ Author : XeroNicHS (Jang Hyun-seung)
//   @ Date   : 2016 / 10 / 26 - v0.1
//              -> 프로토타입 완성
//-------------------------------------------------------------------

#include <Windows.h>

#include "pluginsdk\_plugins.h"

#ifdef _WIN64
#pragma comment(lib, "pluginsdk\\x64dbg.lib")
#pragma comment(lib, "pluginsdk\\x64bridge.lib")
#else
#pragma comment(lib, "pluginsdk\\x32dbg.lib")
#pragma comment(lib, "pluginsdk\\x32bridge.lib")
#endif	// _WIN64

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif	// DLL_EXPORT
//-------------------------------------------------------------------
#define plugin_name "AttachHelper"
#define plugin_version 1

#define MENU_ABOUT	0

//-------------------------------------------------------------------
HINSTANCE g_hDllInst;

int g_iPluginHandle;

HWND g_hwndDlg;
int g_hMenu;

//-------------------------------------------------------------------
#ifdef __cplusplus
extern "C"
{
#endif

	DLL_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct);
	DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct);
	DLL_EXPORT bool plugstop(void);

	DLL_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY *info);
	DLL_EXPORT void CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH *info);

#ifdef __cplusplus
}
#endif

//-------------------------------------------------------------------
// Plugin Export Functions
//-------------------------------------------------------------------
DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
	initStruct->sdkVersion = PLUG_SDKVERSION;
	initStruct->pluginVersion = plugin_version;
	strcpy_s(initStruct->pluginName, 256, plugin_name);
	g_iPluginHandle = initStruct->pluginHandle;

	_plugin_logprintf("[AttachHelper] pluginHandle : %d\n", g_iPluginHandle);

	return true;
}

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct)
{
	g_hwndDlg = setupStruct->hwndDlg;
	g_hMenu = setupStruct->hMenu;

	_plugin_menuaddentry(g_hMenu, MENU_ABOUT, "About");
}

DLL_EXPORT bool plugstop(void)
{
	_plugin_menuclear(g_hMenu);

	return true;
}

//-------------------------------------------------------------------
DLL_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY *info)
{
	switch (info->hEntry)
	{
	case MENU_ABOUT:
		MessageBox(g_hwndDlg, L"Attach Helper v0.1 [for x64dbg] \r\n\r\n"
			L"Author : Jang Hyun-seung [XeroNicHS] \r\n\r\n"
			L"E-Mail : janghs1117@naver.com \r\n\r\n"
			L"BLOG   : http://www.xeronichs.com",
			L"AttachHelper", MB_ICONINFORMATION | MB_OK);

		break;
	}
}

DLL_EXPORT void CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH *info)
{
	LPVOID pOri_DbgBrkPoint_Addr = NULL;
	LPVOID pOri_DbgUiDbgRemoteBrk_Addr = NULL;
	DWORD dwOld = 0; 
	SIZE_T dwWritten = 0;
	HANDLE hDebugee = NULL;

	DWORD dwPID = info->dwProcessId;

	HMODULE hNtDll = GetModuleHandle(L"NTDLL.DLL");
	if (hNtDll == NULL) return;

	pOri_DbgBrkPoint_Addr = (LPVOID)GetProcAddress(hNtDll, "DbgBreakPoint");
	pOri_DbgUiDbgRemoteBrk_Addr = (LPVOID)GetProcAddress(hNtDll, "DbgUiRemoteBreakin");
	if ((pOri_DbgBrkPoint_Addr == NULL) || (pOri_DbgUiDbgRemoteBrk_Addr == NULL)) return;

	hDebugee = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPID);
	if (hDebugee == NULL) return;

	if (VirtualProtectEx(hDebugee, pOri_DbgBrkPoint_Addr, 2, PAGE_EXECUTE_READWRITE, &dwOld) == FALSE) return;
	WriteProcessMemory(hDebugee, pOri_DbgBrkPoint_Addr, pOri_DbgBrkPoint_Addr, 2, &dwWritten);
	if (VirtualProtectEx(hDebugee, pOri_DbgBrkPoint_Addr, 2, dwOld, &dwOld) == FALSE) return;

	if (VirtualProtectEx(hDebugee, pOri_DbgUiDbgRemoteBrk_Addr, 20, PAGE_EXECUTE_READWRITE, &dwOld) == FALSE) return;
	WriteProcessMemory(hDebugee, pOri_DbgUiDbgRemoteBrk_Addr, pOri_DbgUiDbgRemoteBrk_Addr, 20, &dwWritten);
	if (VirtualProtectEx(hDebugee, pOri_DbgUiDbgRemoteBrk_Addr, 20, dwOld, &dwOld) == FALSE) return;

	if (hDebugee) CloseHandle(hDebugee);
	hDebugee = NULL;
}

//-------------------------------------------------------------------
// DllMain
//-------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		g_hDllInst = hInst;
		DisableThreadLibraryCalls(g_hDllInst);

		break;

	case DLL_PROCESS_DETACH:

		break;
	}

	return TRUE;
}