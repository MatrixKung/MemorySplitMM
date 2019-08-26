#pragma once
// Windows Headers we need
#include <Windows.h>
#include <winternl.h>

// STD headers we need
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>

// Lib headers we need
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <capstone/include/capstone/capstone.h>

// Our own code
#include "internal/log/log.h"
#include "internal/utils/util.h"
#include "internal/portable exe/PE.h"
#include "internal/process/process.h"
#include "internal/disassembler/disassembler.h"
#include "internal/manual map/manual_map.h"
#include "internal/load library/loadlib.h"

// Make sure we dont use x64 for now
#ifdef _WIN64
#error 64 BIT CURRENTLY NOT SUPPORTED
#endif