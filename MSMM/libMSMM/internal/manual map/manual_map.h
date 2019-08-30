#pragma once
#include "mapped_section.h"

namespace libMSMM
{
	enum MappingOptions
	{
		CLEAR_FILE_MEMORY_FROM_LOCAL_BUFFER = (1 << 0),
		WIPE_IMPORTS = (1 << 1),
		WIPE_RELOCATIONS = (1 << 2),
		LAYOUT_RANDOMISATION = (1 << 3),

		MAP_ALL_OPTIONS = 0xFFFFFFFF
	};
}

namespace libMSMM::mm
{
	bool MapImage(void* pImage, const size_t ImageSize, process::Process& Process, const MappingOptions);
}
