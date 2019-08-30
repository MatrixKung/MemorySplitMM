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

		std::string ModuleName = pModuleName;

		if (ModuleName.substr(0, 14) == "api-ms-win-crt")
		{
			// redirect to c runtime kit path
			ModuleName = "C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x86\\" + ModuleName;
		}

		// Rebase local LoadLibraryA to remote LoadLibraryA
		uint32_t pLoadLibraryRemote = (uint32_t)LocalLoadLibrary - (uint32_t)LocalKernal32 + (uint32_t)RemoteKernal32;
		char* ppLLR = (char*)& pLoadLibraryRemote;

		auto DLLNameSize = strlen(ModuleName.c_str()) + 1;
		auto pRemoteDLLName = Process.AllocateMemory(DLLNameSize, PAGE_READWRITE);
		Process.WriteMemory((void*)ModuleName.data(), pRemoteDLLName, DLLNameSize);

		auto Thread = CreateRemoteThread(Process.GetHandle(), NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryRemote, (LPVOID)pRemoteDLLName, NULL, NULL);

		if (!Thread)
		{
			LOG_ERROR("Failed to run remote loadlibrary on {}", ModuleName);
			Process.FreeMemory(pRemoteDLLName);
			return 0;
		}

		WaitForSingleObject(Thread, INFINITE);

		std::this_thread::sleep_for(0.5s);

		Process.FreeMemory(pRemoteDLLName);
		auto Module = (HMODULE)Process.GetRemoteModule(pModuleName);
		if (!Module)
		{
			LOG_ERROR("Failed to load module {}: {}", ModuleName, GetLastError());
			return 0;
		}
		return Module;
	}
};