#include <pch.h>

namespace libMSMM::ll
{
	HMODULE LoadLibraryRemote(process::Process& Process, const char* pModuleName)
	{
		auto RemoteKernal32 = Process.GetRemoteModule("kernel32.dll");
		if (!RemoteKernal32)
		{
			LOG_ERROR("Could not find Remote kernel32.dll");
			return nullptr;
		}

		auto LocalKernal32 = GetModuleHandleA("kernel32.dll");
		if (!LocalKernal32)
		{
			LOG_ERROR("Could not find Local kernel32.dll");
			return nullptr;
		}

		auto LocalLoadLibrary = GetProcAddress(LocalKernal32, "LoadLibraryA");
		if (!LoadLibraryA)
		{
			LOG_ERROR("Could not find Local LoadLibraryA");
			return nullptr;
		}

		// Rebase local LoadLibraryA to remote LoadLibraryA
		uint32_t pLoadLibraryRemote = (uint32_t)LocalLoadLibrary - (uint32_t)LocalKernal32 + (uint32_t)RemoteKernal32;
		char* ppLLR = (char*)& pLoadLibraryRemote;

		auto DLLNameSize = strlen(pModuleName) + 1;
		auto pRemoteDLLName = Process.AllocateMemory(DLLNameSize, PAGE_READWRITE);
		Process.WriteMemory((void*)pModuleName, pRemoteDLLName, DLLNameSize);

		auto Thread = CreateRemoteThread(Process.GetHandle(), NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryRemote, (LPVOID)pRemoteDLLName, NULL, NULL);

		if (!Thread)
		{
			LOG_ERROR("Failed to run remote loadlibrary on {}", pModuleName);
			Process.FreeMemory(pRemoteDLLName);
			return 0;
		}

		WaitForSingleObject(Thread, INFINITE);

		Process.FreeMemory(pRemoteDLLName);

		auto Module = (HMODULE)Process.GetRemoteModule(pModuleName);
		if (!Module)
		{
			LOG_ERROR("Failed to load module {}: {}", pModuleName, GetLastError());
			return 0;
		}
		return Module;
	}
};