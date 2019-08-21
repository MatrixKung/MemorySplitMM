#pragma once

namespace libMSMM::process
{
	class Process
	{
	public:
		Process();
		Process(int, HANDLE);

		bool is_valid() const;
		int get_id() const;
		HANDLE get_handle() const;
	private:

		int m_ProcessId;
		HANDLE m_hOpenedProcess;

	};

	Process Find(const char* ProcExeName);
}