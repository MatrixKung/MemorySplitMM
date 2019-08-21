#pragma once

namespace libMSMM::mm
{
	class MappedSection
	{
	public:
		MappedSection() = delete;
		MappedSection(IMAGE_SECTION_HEADER Header, process::Process& Process);
		~MappedSection();

		MappedSection(const MappedSection& Copy);

		bool is_valid() const;
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
}