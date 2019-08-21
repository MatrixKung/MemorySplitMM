#include <pch.h>

namespace libMSMM::mm
{
	MappedSection::MappedSection(IMAGE_SECTION_HEADER Header, process::Process& Process) :
		m_Header(Header),
		m_hProcess(Process),
		m_isRemoteLocked(false),
		m_isLocalLocked(false)
	{
		const auto AllocSize = m_Header.SizeOfRawData;
		DWORD MemoryProtection = PAGE_READWRITE;

		if (m_Header.Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			MemoryProtection = PAGE_EXECUTE_READWRITE;
		}

		m_pLocalAllocation = VirtualAlloc(nullptr, AllocSize, MEM_COMMIT | MEM_RESERVE, MemoryProtection);
		m_pRemoteAllocation = VirtualAllocEx(Process.get_handle(), nullptr, AllocSize, MEM_COMMIT | MEM_RESERVE, MemoryProtection);

		LOG_INFO("Allocated {}\t size=0x{:08x} virtual=0x{:08x} local=0x{:08x} remote={:08x}",
			std::string((char*)m_Header.Name).substr(0, 7),
			m_Header.SizeOfRawData,
			m_Header.VirtualAddress,
			(uint32_t)m_pLocalAllocation,
			(uint32_t)m_pRemoteAllocation
		);
	}

	MappedSection::~MappedSection()
	{
		if (m_pLocalAllocation && !m_isLocalLocked)
		{
			VirtualFree(m_pLocalAllocation, NULL, MEM_RELEASE);
			LOG_TRACE("FREED LOCAL ALLOCATION OF {}", m_Header.Name);
		}

		if (m_pRemoteAllocation && !m_isRemoteLocked)
		{
			VirtualFreeEx(m_hProcess.get_handle(), m_pRemoteAllocation, NULL, MEM_RELEASE);
			LOG_TRACE("FREED REMOTE ALLOCATION OF {}", m_Header.Name);
		}
	}

	MappedSection::MappedSection(const MappedSection& Copy) :
		m_Header(Copy.m_Header),
		m_hProcess(Copy.m_hProcess),
		m_isRemoteLocked(false),
		m_isLocalLocked(false),
		m_pLocalAllocation(Copy.m_pLocalAllocation),
		m_pRemoteAllocation(Copy.m_pRemoteAllocation)
	{
		Copy.m_isLocalLocked = true;
		Copy.m_isRemoteLocked = true;
	}

	bool MappedSection::is_valid() const
	{
		// if the header is of size 0, we cant allocate it, 
		// but we still want it to be a valid section
		if (m_Header.SizeOfRawData == 0)
			return true;

		return m_pLocalAllocation && m_pRemoteAllocation;
	}

	void MappedSection::lock_remote()
	{
		m_isRemoteLocked = true;
	}
}