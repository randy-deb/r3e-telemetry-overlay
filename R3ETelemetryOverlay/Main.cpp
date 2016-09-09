// Library for drawing information from the game shared memory
// ingame using D3D9 API hooks.
//
// Copyright 2015-2016 Deborggraeve Randy. All Rights Reserved.

#include <Windows.h>
#include <d3d9.h>
#include <r3e.h>
#include <stdio.h>
#include <thread>
#include <atomic>
#include "Detours/detours.h"

#define CUSTOMFVF (D3DFVF_XYZRHW | D3DFVF_DIFFUSE)

struct CUSTOMVERTEX
{
	FLOAT x;
	FLOAT y;
	FLOAT z;
	FLOAT rhw;
	DWORD color;
};

// API call prototypes
extern "C" typedef HRESULT(WINAPI* DIRECT3DDEVICE9_ENDSCENE)(LPDIRECT3DDEVICE9);

// API call storage
DIRECT3DDEVICE9_ENDSCENE Orig_Direct3DDevice9_EndScene = NULL;

// Shared memory objects
HANDLE g_SharedMemory = NULL;
r3e_shared* g_SharedMemoryBuffer = NULL;

// The overlay thread
std::thread g_OverlayThread;
std::atomic_bool g_OverlayThreadRunning{ true };

inline void WriteLog(char* msg)
{
	FILE* file = NULL;
	fopen_s(&file, "d:\\Repositories\\Tools\\log.txt", "w");
	fprintf(file, msg);
	fflush(file);
	fclose(file);
}

inline r3e_shared* TryGetSharedMemory()
{
	// Try map the shared memory
	if (g_SharedMemoryBuffer == NULL)
	{
		if (g_SharedMemory == NULL)
		{
			g_SharedMemory = OpenFileMapping(FILE_MAP_READ, FALSE, TEXT(R3E_SHARED_MEMORY_NAME));
			if (g_SharedMemory != NULL)
			{
				g_SharedMemoryBuffer = (r3e_shared*)MapViewOfFile(g_SharedMemory, FILE_MAP_READ, 0, 0, sizeof(r3e_shared));
			}
		}
	}
	return g_SharedMemoryBuffer;
}

HRESULT WINAPI Hook_Direct3DDevice9_EndScene(LPDIRECT3DDEVICE9 pD3DDevice)
{
	// Get the shared memory
	auto r3esm = TryGetSharedMemory();

	//TODO: Draw the info from the shared memory to the screen
	//	- Tire temp
	//	- Brake temp
	//	- ...
	CUSTOMVERTEX vertices[] =
	{
		{ 10.0f, 10.0f, 1.0f, 1.0f, D3DCOLOR_XRGB(0, 0, 255), },
		{ 50.0f, 10.0f, 1.0f, 1.0f, D3DCOLOR_XRGB(0, 255, 0), },
		{ 10.0f, 50.0f, 1.0f, 1.0f, D3DCOLOR_XRGB(255, 0, 0), },

		{ 10.0f, 50.0f, 1.0f, 1.0f, D3DCOLOR_XRGB(255, 0, 0), },
		{ 50.0f, 10.0f, 1.0f, 1.0f, D3DCOLOR_XRGB(0, 255, 0), },
		{ 50.0f, 50.0f, 1.0f, 1.0f, D3DCOLOR_XRGB(255, 0, 255), },
	};
	pD3DDevice->SetFVF(CUSTOMFVF);
	pD3DDevice->DrawPrimitiveUP(D3DPT_TRIANGLELIST, 2, vertices, sizeof(CUSTOMVERTEX));

	return Orig_Direct3DDevice9_EndScene(pD3DDevice);
}

DWORD** FindDevice(DWORD Base, DWORD Len)
{
	unsigned long i = 0, n = 0;

	for (i = 0; i < Len; i++)
	{
		if (*(BYTE *)(Base + i + 0x00) == 0xC7)n++;
		if (*(BYTE *)(Base + i + 0x01) == 0x06)n++;
		if (*(BYTE *)(Base + i + 0x06) == 0x89)n++;
		if (*(BYTE *)(Base + i + 0x07) == 0x86)n++;
		if (*(BYTE *)(Base + i + 0x0C) == 0x89)n++;
		if (*(BYTE *)(Base + i + 0x0D) == 0x86)n++;

		if (n == 6) return (DWORD**)
			(Base + i + 2); n = 0;
	}
	return(0);
}

void AttachOverlay()
{
	WriteLog("Attach overlay");

	// Wait for the D3D module to be loaded
	HMODULE hD3DModule = NULL;
	while (hD3DModule == NULL)
	{
		hD3DModule = GetModuleHandle(TEXT("d3d9.dll"));
		if (hD3DModule == NULL)
		{
			WriteLog("Waiting for D3D9.dll to be loaded");
			Sleep(100);
		}
	}
	WriteLog("D3D9.dll has been loaded");

	DWORD** VTable = NULL;
	DWORD** VtablePtr = FindDevice((DWORD)hD3DModule, 0x128000);
	*(DWORD_PTR *)&VTable = *(DWORD_PTR *)VtablePtr;
	Orig_Direct3DDevice9_EndScene = (DIRECT3DDEVICE9_ENDSCENE)VTable[42];
	if (Orig_Direct3DDevice9_EndScene == NULL)
	{
		WriteLog("Failed to get the IDirect3DDevice9::EndScene method from the VTable");
		return;
	}

	// Hook the API calls
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Orig_Direct3DDevice9_EndScene, Hook_Direct3DDevice9_EndScene);
	DetourTransactionCommit();
}

void DetachOverlay()
{
	WriteLog("Detach overlay");

	// Unhook the API calls
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)Orig_Direct3DDevice9_EndScene, Hook_Direct3DDevice9_EndScene);
	DetourTransactionCommit();

	// Close the shared memory
	if (g_SharedMemoryBuffer != NULL)
	{
		UnmapViewOfFile(g_SharedMemoryBuffer);
		g_SharedMemoryBuffer = NULL;
	}
	if (g_SharedMemory != NULL)
	{
		CloseHandle(g_SharedMemory);
		g_SharedMemory = NULL;
	}
}

void RenderGameOverlay()
{
	AttachOverlay();
	while (g_OverlayThreadRunning)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	DetachOverlay();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		//g_OverlayThreadRunning = true;
		//g_OverlayThread = std::thread(RenderGameOverlay);
		AttachOverlay();
		break;
	case DLL_PROCESS_DETACH:
		/*
		if (g_OverlayThread.joinable())
		{
			g_OverlayThreadRunning = false;
			g_OverlayThread.join();
		}
		*/
		DetachOverlay();
		break;
	}

	return TRUE;
}