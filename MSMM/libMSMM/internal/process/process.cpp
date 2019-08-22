#include <pch.h>
#include <tlhelp32.h>

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
		return GetModuleHandle(pModuleName);
	}
	uint32_t Process::GetRemoteFunction(HMODULE pModule, const char* pFunctionName)
	{
		return (uint32_t)GetProcAddress(pModule, pFunctionName);
	}
}