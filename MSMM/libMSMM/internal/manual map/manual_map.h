#pragma once
#include "mapped_section.h"

namespace libMSMM::mm
{
	bool MapImage(void* pImage, const size_t ImageSize, process::Process& Process);
}
