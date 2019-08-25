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
		// read DOS header
		IMAGE_DOS_HEADER DosHeader;
		if (!ReadProcessMemory(m_hOpenedProcess, pModule, &DosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))
		{
			LOG_ERROR("Read DOS Header failed!");
			return 0;
		}

		// read nt header
		IMAGE_NT_HEADERS32 NTHeader;
		if (!ReadProcessMemory(m_hOpenedProcess, (char*)pModule + DosHeader.e_lfanew, &NTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr))
		{
			LOG_ERROR("Read NT Header failed!");
			return 0;
		}

		// get export dir
		IMAGE_DATA_DIRECTORY ExportDataDir = NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		
		if (ExportDataDir.VirtualAddress == 0)
		{
			LOG_ERROR("image does not have a export data directory!");
			return 0;
		}

		IMAGE_EXPORT_DIRECTORY ExportDirectory;

		if (!ReadProcessMemory(m_hOpenedProcess, (char*)pModule + ExportDataDir.VirtualAddress, &ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
		{
			LOG_ERROR("Read Export Directory failed!");
			return 0;
		}

		const auto NumberOfFunctions = ExportDirectory.NumberOfFunctions;
		const auto NumberOfNames = ExportDirectory.NumberOfNames;

		uint32_t* pNames = (uint32_t*)malloc(NumberOfNames * sizeof(uint32_t));
		if (!pNames)
		{
			LOG_ERROR("failed to allocate name directory!");
			return 0;
		}

		uint16_t* pNameOrdinals = (uint16_t*)malloc(NumberOfNames * sizeof(uint16_t));
		if (!pNameOrdinals)
		{
			LOG_ERROR("failed to allocate name directory!");
			return 0;
		}

		uint32_t* pFunctions = (uint32_t*)malloc(NumberOfFunctions * sizeof(uint32_t));
		if (!pFunctions)
		{
			LOG_ERROR("failed to allocate function directory!");
			return 0;
		}

		if (!ReadProcessMemory(m_hOpenedProcess, (char*)pModule + ExportDirectory.AddressOfNames, pNames, NumberOfNames * sizeof(uint32_t), nullptr))
		{
			LOG_ERROR("Read Name Directory failed!");
			return 0;
		}

		if (!ReadProcessMemory(m_hOpenedProcess, (char*)pModule + ExportDirectory.AddressOfNameOrdinals, pNameOrdinals, NumberOfNames * sizeof(uint16_t), nullptr))
		{
			LOG_ERROR("Read Ordinal Directory failed!");
			return 0;
		}

		if (!ReadProcessMemory(m_hOpenedProcess, (char*)pModule + ExportDirectory.AddressOfFunctions, pFunctions, NumberOfFunctions * sizeof(uint32_t), nullptr))
		{
			LOG_ERROR("Read Function Directory failed!");
			return 0;
		}

		for (auto i = 0; i < NumberOfNames; i++)
		{
			char FunctionName[4096] = { 0 };
			
			if (!ReadProcessMemory(m_hOpenedProcess, (char*)pModule + pNames[i], FunctionName, 4096, nullptr))
			{
				LOG_ERROR("Read Function Name failed!");
				return 0;
			}

			if (!strcmp(FunctionName, pFunctionName))
			{
				auto NameOrdinal = pNameOrdinals[i];
				auto OptFn = (uint32_t)pModule + pFunctions[NameOrdinal];
				if (OptFn != (uint32_t)GetProcAddress(pModule, pFunctionName)) // todo - replace!!
				{
					// forwarded export
					if (!ReadProcessMemory(m_hOpenedProcess, (void*)OptFn, FunctionName, 4096, nullptr))
					{
						LOG_ERROR("Read forwarded export failed!");
						return 0;
					}

					// FunctionName in format DLL.Function
					std::string FuncName = FunctionName;
					std::string DLLName = FuncName.substr(0, FuncName.find('.')) + ".dll";
					FuncName = FuncName.substr(FuncName.find('.') + 1);

					auto FowardModule = GetRemoteModule(DLLName.c_str());
					if (!FowardModule)
					{
						LOG_ERROR("could not foward function");
					}

					return GetRemoteFunction(FowardModule, FuncName.c_str());
				}
				return OptFn;
			}
		}

		LOG_ERROR("failed to find function!");

		return 0;
	}
	HANDLE Process::GetHandle() const
	{
		return m_hOpenedProcess;
	}
}