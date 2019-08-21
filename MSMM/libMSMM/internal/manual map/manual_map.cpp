#include <pch.h>

namespace libMSMM::mm
{
	bool MapImage(void* pImage, const size_t ImageSize, process::Process& Process)
	{
		LOG_DEBUG("starting map");

		// Grab our headers
		const auto dosHeader = PE::GetDOSHeaders(pImage);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			LOG_ERROR("Image DOS Header Currupt");
			return false;
		}

		const auto ntHeader = PE::GetNTHeaders(pImage);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			LOG_ERROR("Image NT Header Currupt");
			return false;
		}

		const auto nSectionCount = ntHeader->FileHeader.NumberOfSections;
		const PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(ntHeader);

		// when this goes out of scope it will deallocate all sections 
		// for us unless we 'lock' the remote address - which we do once
		// we know everything else is done
		LOG_DEBUG("allocating sections");
		std::vector<sections::MappedSection> SectionDirectory;

		for (auto i = 0; i < nSectionCount; i++)
		{
			auto Section = sections::MappedSection(pSections[i], Process);

			if (!Section.is_valid())
			{
				LOG_ERROR("Could not allocate section properly!");
				return false;
			}

			SectionDirectory.push_back(Section);
		}

		// temp - allocate a backup section which can be used to fallback on when we dont know where the hell a address is
		IMAGE_SECTION_HEADER BackupSectionHeader;
		BackupSectionHeader.Name[0] = 0; // ""
		BackupSectionHeader.VirtualAddress = 0;
		BackupSectionHeader.SizeOfRawData = ntHeader->OptionalHeader.SizeOfImage;

		auto BackupSection = sections::MappedSection(BackupSectionHeader, Process);

		if (!BackupSection.is_valid())
		{
			LOG_ERROR("Could not allocate section properly!");
			return false;
		}
		SectionDirectory.push_back(BackupSection);

		LOG_DEBUG("allocated sections");

		LOG_DEBUG("writing image to local sections");
		for (auto& Section : SectionDirectory)
		{
			if (Section.Header().VirtualAddress) // skip our backup section (which has a VA of 0)
			{
				if (auto pSectionData = Section.GetLocalAllocation()) // some sections may be size0 and not get allocated!
				{
					LOG_TRACE("wrote {}", std::string((char*)Section.Header().Name).substr(0, 7));
					auto pImageData = (void*)((uint32_t)pImage + Section.Header().PointerToRawData);
					memcpy(pSectionData, pImageData, Section.Header().SizeOfRawData);
				}
			}
		}
		LOG_DEBUG("all local sections written");

		//LOG_DEBUG("starting standard relocations");
		//LOG_DEBUG("finsihed standard relocations");

		LOG_DEBUG("finished map");
		return true;
	}
}
