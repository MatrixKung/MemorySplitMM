#pragma once

namespace libMSMM::disassembler
{
	bool disassemble(void* pCode, size_t CodeSize, std::vector<cs_insn>& output);
}