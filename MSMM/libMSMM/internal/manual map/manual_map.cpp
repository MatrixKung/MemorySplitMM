#include <pch.h>

namespace libMSMM::mm
{
	bool MapImage(void* pImage, const size_t ImageSize, process::Process& Process)
	{
		LOG_TRACE("starting map");

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
		// for us unless we 'lock' the remote address
		std::vector<MappedSection> SectionDirectory;

		for (auto i = 0; i < nSectionCount; i++)
		{
			auto Section = MappedSection(pSections[i], Process);

			if (!Section.is_valid())
			{
				LOG_ERROR("Could not allocate section properly!");
				return false;
			}

			SectionDirectory.push_back(Section);
		}

		LOG_TRACE("finished map");
		return true;
	}
}
