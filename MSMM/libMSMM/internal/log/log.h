#pragma once

#ifdef _DEBUG
#define LOG_DEBUG_LEVEL spdlog::level::trace
#else
#define LOG_DEBUG_LEVEL spdlog::level::warn
#endif

namespace libMSMM
{
	namespace log
	{
		extern std::shared_ptr<spdlog::logger> Logger;

		void Setup(spdlog::level::level_enum DebugLevel);
	}

#define LOG_CRITICAL(...)	libMSMM::log::Logger->critical(__VA_ARGS__)
#define LOG_ERROR(...)		libMSMM::log::Logger->error(__VA_ARGS__)
#define LOG_WARN(...)		libMSMM::log::Logger->warn(__VA_ARGS__)
#define LOG_INFO(...)		libMSMM::log::Logger->info(__VA_ARGS__)
#define LOG_DEBUG(...)		libMSMM::log::Logger->debug(__VA_ARGS__)
#define LOG_TRACE(...)		libMSMM::log::Logger->trace(__VA_ARGS__)
}