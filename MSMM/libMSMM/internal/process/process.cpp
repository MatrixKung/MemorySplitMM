#include <pch.h>
#include <tlhelp32.h>
#include <Psapi.h>

namespace libMSMM::process
{
	Process Find(const char* ProcExeName)
	{
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		int ProcessId = 0;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				if (strcmp(entry.szExeFile, ProcExeName) == 0)
				{
					ProcessId = entry.th32ProcessID;
				}
			}
		}

		CloseHandle(snapshot);

		if (ProcessId == 0)
		{
			return Process();
		}

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

		return Process(ProcessId, hProcess);
	}

	Process::Process() :
		m_ProcessId( 0 ),
		m_hOpenedProcess( 0 )
	{
	}
	Process::Process(int procid, HANDLE handle) :
		m_ProcessId(procid),
		m_hOpenedProcess(handle)
	{
	}
	Process::~Process()
	{
		if (m_hOpenedProcess)
		{
			CloseHandle(m_hOpenedProcess);
		}
	}

	bool Process::is_valid() const
	{
		return m_ProcessId && m_hOpenedProcess;
	}

	int Process::get_id() const
	{
		return m_ProcessId;
	}
	void* Process::AllocateMemory(size_t Size, DWORD protection)
	{
		return VirtualAllocEx(m_hOpenedProcess, nullptr, Size, MEM_COMMIT | MEM_RESERVE, protection);
	}
	void Process::FreeMemory(void* pMemory)
	{
		VirtualFree(pMemory, NULL, MEM_RELEASE);
	}
	void Process::WriteMemory(void* pLocalBuffer, void* pDestBuffer, size_t BufferSize)
	{
		WriteProcessMemory(m_hOpenedProcess, pDestBuffer, pLocalBuffer, BufferSize, nullptr);
	}
	HMODULE Process::GetRemoteModule(const char* pModuleName)
	{
		//BOOL EnumProcessModules(
		//	HANDLE  hProcess,
		//	HMODULE * lphModule,
		//	DWORD   cb,
		//	LPDWORD lpcbNeeded
		//);
		constexpr auto ModuleListSize = 1000;
		HMODULE ModuleList[ModuleListSize] = { 0 };
		constexpr auto CB = ModuleListSize * sizeof(HMODULE);

		std::string DesiredModule = pModuleName;
		std::transform(DesiredModule.begin(), DesiredModule.end(), DesiredModule.begin(), tolower);


		DWORD cbNeeded = 0;
		if (K32EnumProcessModules(m_hOpenedProcess, ModuleList, CB, &cbNeeded))
		{
			for (auto i = 0; i < cbNeeded / sizeof(HMODULE); i++)
			{
				auto Module = ModuleList[i];

				if (Module)
				{
					char ModuleFileName[128] = { 0 };
					if (K32GetModuleFileNameExA(m_hOpenedProcess, Module, ModuleFileName, 128))
					{
						std::string ModuleFileNameNoPath = ModuleFileName;
						ModuleFileNameNoPath = ModuleFileNameNoPath.substr(ModuleFileNameNoPath.find_last_of('\\') + 1);

						std::transform(ModuleFileNameNoPath.begin(), ModuleFileNameNoPath.end(), ModuleFileNameNoPath.begin(), tolower);

						if (strcmp(DesiredModule.c_str(), ModuleFileNameNoPath.c_str()) == 0)
						{
							return Module;
						}
					}
					else
					{
						LOG_ERROR("K32GetModuleFileNameExA failed - maybe can continue?");
					}
				}
			}
		}
		else
		{
			LOG_ERROR("K32EnumProcessModules failed!");
			return nullptr;
		}
	}
	uint32_t Process::GetRemoteFunction(HMODULE pModule, const char* pFunctionName)
	{
		return (uint32_t)GetProcAddress(pModule, pFunctionName);
	}
}