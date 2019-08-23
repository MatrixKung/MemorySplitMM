#include <pch.h>

namespace libMSMM::mm::sections
{
	MappedSection::MappedSection(IMAGE_SECTION_HEADER Header, process::Process& Process) :
		m_Header(Header),
		m_hProcess(Process),
		m_isRemoteLocked(false),
		m_isLocalLocked(false),
		m_pLocalAllocation(0),
		m_pRemoteAllocation(0),
		m_AllocationSize(Header.SizeOfRawData)
	{
		if (m_AllocationSize > 0) // dont bother allocating nothing
		{
			DWORD MemoryProtection = PAGE_READWRITE;

			if (m_Header.Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				MemoryProtection = PAGE_EXECUTE_READWRITE;
			}

			m_pLocalAllocation = VirtualAlloc(nullptr, m_AllocationSize, MEM_COMMIT | MEM_RESERVE, MemoryProtection);
			m_pRemoteAllocation = Process.AllocateMemory(m_AllocationSize, MemoryProtection);
		}

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
			m_pLocalAllocation = nullptr;
			LOG_TRACE("FREED LOCAL ALLOCATION OF {}", m_Header.Name);
		}

		if (m_pRemoteAllocation && !m_isRemoteLocked)
		{
			m_hProcess.FreeMemory(m_pRemoteAllocation);
			m_pRemoteAllocation = nullptr;
			LOG_TRACE("FREED REMOTE ALLOCATION OF {}", m_Header.Name);
		}
	}

	MappedSection::MappedSection(const MappedSection& Copy) :
		m_Header(Copy.m_Header),
		m_hProcess(Copy.m_hProcess),
		m_isRemoteLocked(false),
		m_isLocalLocked(false),
		m_pLocalAllocation(Copy.m_pLocalAllocation),
		m_pRemoteAllocation(Copy.m_pRemoteAllocation),
		m_AllocationSize(Copy.m_AllocationSize)
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

	void* MappedSection::GetLocalAllocation() const
	{
		return m_pLocalAllocation;
	}

	void* MappedSection::GetRemoteAllocation() const 
	{
		return m_pRemoteAllocation;
	}

	const IMAGE_SECTION_HEADER& MappedSection::Header() const
	{
		return m_Header;
	}

	void MappedSection::WriteSectionToRemote()
	{
		m_hProcess.WriteMemory( m_pLocalAllocation, m_pRemoteAllocation, m_AllocationSize );
	}

	void MappedSection::lock_remote()
	{
		m_isRemoteLocked = true;
	}

	bool MappedSection::does_contain_va(DWORD VA) const
	{
		auto SectionVA = m_Header.VirtualAddress;
		auto SectionSize = m_Header.SizeOfRawData;
		if (SectionVA <= VA && SectionVA + SectionSize > VA)
		{
			return true;
		}

		return false;
	}

	const MappedSection& VAToSec(const SectionDir& Sections, uint32_t VA)
	{
		for (auto& Section : Sections)
		{
			auto SectionVA = Section.Header().VirtualAddress;
			auto SectionSize = Section.Header().SizeOfRawData;
			if (SectionVA <= VA && SectionVA + SectionSize > VA)
			{
				return Section;
			}
		}

		return Sections.back(); // if we fail - return the last section (we assume this is the backup section)
	}
	const MappedSection& LocalToSec(const SectionDir& Sections, uint32_t Local)
	{
		for (auto& Section : Sections)
		{
			auto SectionLocation = (DWORD)Section.GetLocalAllocation();
			auto SectionSize = Section.Header().SizeOfRawData;
			if (SectionLocation <= Local && SectionLocation + SectionSize > Local)
			{
				return Section;
			}
		}

		return Sections.back(); // if we fail - return the last section (we assume this is the backup section)
	}
	const MappedSection& RemoteToSec(const SectionDir& Sections, uint32_t Remote)
	{
		for (auto& Section : Sections)
		{
			auto SectionLocation = (DWORD)Section.GetRemoteAllocation();
			auto SectionSize = Section.Header().SizeOfRawData;
			if (SectionLocation <= Remote && SectionLocation + SectionSize > Remote)
			{
				return Section;
			}
		}

		return Sections.back(); // if we fail - return the last section (we assume this is the backup section)
	}
}