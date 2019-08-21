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

		void* GetLocalAllocation();
		void* GetRemoteAllocation();
		const IMAGE_SECTION_HEADER& Header() const;

		void WriteSectionToRemote();
		void lock_remote();

		template<typename T>
		T RelocateVAToLocal(DWORD VA) const
		{
			return (T)(VA + (DWORD)m_pLocalAllocation);
		}
		template<typename T>
		T RelocateVAToRemote(DWORD VA) const
		{
			return (T)(VA + (DWORD)m_pRemoteAllocation);
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

	const MappedSection& VAToSec(const SectionDir& Sections, DWORD VA);

	template<typename T = void*>
	T VAToLocalPtr(const SectionDir& Sections, DWORD VA)
	{
		auto& Sec = VAToSec(Sections, VA);
		return Sec.RelocateVAToLocal<T>(VA);
	}

	template<typename T = void*>
	T VAToRemotePtr(const SectionDir& Sections, DWORD VA)
	{
		const auto& Sec = VAToSec(Sections, VA);
		return Sec.RelocateVAToRemote<T>(VA);
	}
}