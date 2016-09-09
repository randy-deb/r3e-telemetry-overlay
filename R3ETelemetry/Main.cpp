// Tool for detecting the game executable and attaching the 
// overlay rendering library to the game.
//
// Copyright 2015-2016 Deborggraeve Randy. All Rights Reserved.

#include <Windows.h>
#include <shellapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>

std::atomic_bool g_Running;
std::mutex g_coutMutex;

HANDLE FindGameProcess()
{
	// Take a snapshot of all processes in the system.
	HANDLE hProcess = NULL;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		// Find the process
		PROCESSENTRY32 entry;
		memset(&entry, 0, sizeof(PROCESSENTRY32));
		entry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnap, &entry))
		{
			do
			{
				if (_tcscmp(entry.szExeFile, TEXT("DX9Sample.exe")) == 0)
				{
					hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
					break;
				}
			} while (Process32Next(hProcessSnap, &entry));
		}

		// Close the snapshot handle
		CloseHandle(hProcessSnap);
	}

	// Return the result
	return hProcess;
}

HMODULE FindModule(HANDLE hProcess)
{
	// Take a snapshot of all processes in the system.
	HMODULE hModule = NULL;
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
	if (hModuleSnap != INVALID_HANDLE_VALUE)
	{
		// Find the module
		MODULEENTRY32 entry;
		memset(&entry, 0, sizeof(MODULEENTRY32));
		entry.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hModuleSnap, &entry))
		{
			do
			{
				if (_tcscmp(entry.szModule, TEXT("R3ETelemetryOverlay.dll")) == 0)
				{
					hModule = entry.hModule;
					break;
				}
			} while (Module32Next(hModuleSnap, &entry));
		}
	}

	return hModule;
}

void AttachOverlay(HANDLE hProcess)
{
	// Get the overlay module path
	char szModuleFilename[MAX_PATH];
	char szDrive[_MAX_DRIVE];
	char szDirectory[_MAX_DIR];
	GetModuleFileNameA(NULL, szModuleFilename, MAX_PATH);
	_splitpath_s(szModuleFilename, szDrive, _MAX_DRIVE, szDirectory, _MAX_DIR, NULL, 0, NULL, 0);
	_makepath_s(szModuleFilename, szDrive, szDirectory, "R3ETelemetryOverlay", "dll");

	// Launch the remote thread
	LPVOID pAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	LPVOID pParam = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(szModuleFilename), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	BOOL b = WriteProcessMemory(hProcess, pParam, szModuleFilename, strlen(szModuleFilename), NULL);
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddr, pParam, 0, NULL);
	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, NULL, strlen(szModuleFilename), MEM_RESERVE | MEM_COMMIT);
}

void DetachOverlay(HANDLE hProcess)
{
	// Find the module
	HMODULE hOverlayModule = FindModule(hProcess);
	if (hOverlayModule != NULL)
	{
		// Launch the remote thread
		LPVOID pAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
		HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddr, (void*)hOverlayModule, 0, NULL);
		WaitForSingleObject(hRemoteThread, INFINITE);
		CloseHandle(hRemoteThread);
	}
}

void OnGameStarted(HANDLE hProcess)
{
	// Log
	{
		std::lock_guard<std::mutex> coutGuard(g_coutMutex);
		std::cout << "Attaching overlay to game" << std::endl;
	}

	// Attach the overlay
	AttachOverlay(hProcess);
}

void OnGameStopped(HANDLE hProcess)
{
	// Log
	{
		std::lock_guard<std::mutex> coutGuard(g_coutMutex);
		std::cout << "Detaching overlay from game" << std::endl;
	}

	// Detach the overlay
	DetachOverlay(hProcess);
}

void CheckGameRunning()
{
	HANDLE hGameProcess = NULL;

	g_Running = true;
	while (g_Running)
	{
		// Try to get the game process handle
		if (hGameProcess == NULL)
		{
			hGameProcess = FindGameProcess();
			if (hGameProcess != NULL)
			{
				// Trigger the event
				OnGameStarted(hGameProcess);
			}
		}
		else
		{
			// Check if the game is still running
			DWORD exitCode = 0;
			if (GetExitCodeProcess(hGameProcess, &exitCode))
			{
				if (exitCode != STILL_ACTIVE)
				{
					// Trigger the event
					OnGameStopped(hGameProcess);

					// Close the game process handle
					CloseHandle(hGameProcess);
					hGameProcess = NULL;

					continue;
				}
			}
		}

		// Delay the thread
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	// Make sure we detach everything from the game
	if (hGameProcess != NULL)
	{
		OnGameStopped(hGameProcess);
	}
}

int main(int argc, char** argv)
{
	// Start the thread to handle game startup/shutdown
	std::thread checkGameThread(CheckGameRunning);

	// Run the main loop
	while (true)
	{
		int key = _gettch();
		if (key == 27) // escape key
		{
			break;
		}
		else if (key == 97)
		{
			if (!checkGameThread.joinable())
			{
				{
					std::lock_guard<std::mutex> coutGuard(g_coutMutex);
					std::cout << "Starting telemetry overlay" << std::endl;
				}
				checkGameThread = std::thread(CheckGameRunning);
			}
		}
		else if (key == 113)
		{
			if (checkGameThread.joinable())
			{
				{
					std::lock_guard<std::mutex> coutGuard(g_coutMutex);
					std::cout << "Stopping telemetry overlay" << std::endl;
				}
				g_Running = false;
				checkGameThread.join();
			}
		}
	}

	// Wait for the checkGameThread to exit
	if (checkGameThread.joinable())
	{
		g_Running = false;
		checkGameThread.join();
	}

	return 0;
}
