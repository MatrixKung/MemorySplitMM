#pragma once

namespace libMSMM::mm::sections
{
	class MappedSection
	{
	public:
		MappedSection() = delete;
		MappedSection(IMAGE_SECTION_HEADER Header, process::Process& Process);
		~MappedSection();

		MappedSection(const MappedSection& Copy);

		bool is_valid() const;

		void* GetLocalAllocation() const;
		void* GetRemoteAllocation() const;
		const IMAGE_SECTION_HEADER& Header() const;

		void WriteSectionToRemote();
		void lock_remote();
		bool does_contain_va(DWORD VA) const;

		template<typename T>
		T RelocateVAToLocal(DWORD VA) const
		{
			if (!does_contain_va(VA))
				return (T)nullptr;
			return (T)(VA + (DWORD)m_pLocalAllocation - m_Header.VirtualAddress);
		}
		template<typename T>
		T RelocateVAToRemote(DWORD VA) const
		{
			if (!does_contain_va(VA))
				return (T)nullptr;
			return (T)(VA + (DWORD)m_pRemoteAllocation - m_Header.VirtualAddress);
		}

	private:
		IMAGE_SECTION_HEADER m_Header;
		process::Process& m_hProcess;

		// controls if data will be deallocated during destruction of MappedSection
		mutable bool m_isLocalLocked;
		mutable bool m_isRemoteLocked;

		void* m_pRemoteAllocation;
		void* m_pLocalAllocation;
	};

	typedef std::vector<sections::MappedSection> SectionDir;

	const MappedSection& VAToSec(const SectionDir& Sections, uint32_t VA);
	const MappedSection& LocalToSec(const SectionDir& Sections, uint32_t Local);
	const MappedSection& RemoteToSec(const SectionDir& Sections, uint32_t Remote);

	template<typename T = void*>
	T VAToLocalPtr(const SectionDir & Sections, uint32_t VA)
	{
		auto& Sec = VAToSec(Sections, VA);
		return Sec.RelocateVAToLocal<T>(VA);
	}

	template<typename T = void*>
	T VAToRemotePtr(const SectionDir& Sections, uint32_t VA)
	{
		const auto& Sec = VAToSec(Sections, VA);
		return Sec.RelocateVAToRemote<T>(VA);
	}

	template<typename T = void*>
	T LocalToRemotePtr(const SectionDir& Sections, uint32_t Local)
	{
		const auto& Sec = LocalToSec(Sections, Local);
		return (T)(Local - (uint32_t)Sec.GetLocalAllocation() + (uint32_t)Sec.GetRemoteAllocation());
	}

	template<typename T = void*>
	T RemoteToLocalPtr(const SectionDir& Sections, uint32_t Local)
	{
		const auto& Sec = RemoteToSec(Sections, Local);
		return (T)(Local - (uint32_t)Sec.GetRemoteAllocation() + (uint32_t)Sec.GetLocalAllocation());
	}

	template<typename T = void*>
	T LocalToVAPtr(const SectionDir & Sections, uint32_t Local)
	{
		auto& Sec = LocalToSec(Sections, Local);
		return (T)(Local - (uint32_t)Sec.GetLocalAllocation() + (uint32_t)Sec.Header().VirtualAddress);
	}

	template<typename T = void*>
	T RemoteToVAPtr(const SectionDir & Sections, uint32_t Remote)
	{
		auto& Sec = RemoteToSec(Sections, Remote);
		return (T)(Remote - (uint32_t)Sec.GetRemoteAllocation() + (uint32_t)Sec.Header().VirtualAddress);
	}
}