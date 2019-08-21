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
		IMAGE_SECTION_HEADER& Header();

		void WriteSectionToRemote();
		void lock_remote();

	private:
		IMAGE_SECTION_HEADER m_Header;
		process::Process& m_hProcess;

		// controls if data will be deallocated during destruction of MappedSection
		mutable bool m_isLocalLocked;
		mutable bool m_isRemoteLocked;

		void* m_pRemoteAllocation;
		void* m_pLocalAllocation;
	};

	MappedSection& VirtualToSection(const std::vector<MappedSection>& Sections);
}