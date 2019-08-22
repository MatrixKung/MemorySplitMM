#pragma once

namespace libMSMM::process
{
	class Process
	{
	public:
		Process();
		Process(int, HANDLE);
		~Process();

		bool is_valid() const;
		int get_id() const;

		void* AllocateMemory(size_t Size, DWORD protection);
		void FreeMemory(void* pMemory);

		void WriteMemory(void* pLocalBuffer, void* pDestBuffer, size_t BufferSize);
	private:

		int m_ProcessId;
		HANDLE m_hOpenedProcess;
	};

	Process Find(const char* ProcExeName);
}