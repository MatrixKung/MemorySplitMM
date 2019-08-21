#include "pch.h"

namespace libMSMM
{
	namespace log
	{
		std::shared_ptr<spdlog::logger> Logger;

		void Setup(spdlog::level::level_enum DebugLevel)
		{
			spdlog::set_pattern("%^%v%$");
			Logger = spdlog::stdout_color_mt("libMSMM");
			Logger->set_level(DebugLevel);
		}
	}
}
