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
				if (stricmp(entry.szExeFile, ProcExeName) == 0)
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

	bool Process::is_valid() const
	{
		return m_ProcessId && m_hOpenedProcess;
	}

	int Process::get_id() const
	{
		return m_ProcessId;
	}
	HANDLE Process::get_handle() const
	{
		return m_hOpenedProcess;
	}
}