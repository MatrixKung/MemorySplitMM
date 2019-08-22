#include <pch.h>

namespace libMSMM::mm
{
	bool VerifyImage(void* pImage, const size_t ImageSize)
	{
		if (!pImage)
		{
			LOG_ERROR("pImage cannot be NULL");
			return false;
		}

		if (!ImageSize)
		{
			LOG_ERROR("ImageSize cannot be 0");
			return false;
		}

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

		return true;
	}
	
	bool AllocateSections(sections::SectionDir& SectionDirectory, PIMAGE_NT_HEADERS32 ntHeader, process::Process& Process)
	{
		const auto nSectionCount = ntHeader->FileHeader.NumberOfSections;
		const PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(ntHeader);

		// when this goes out of scope it will deallocate all sections 
		// for us unless we 'lock' the remote address - which we do once
		// we know everything else is done
		LOG_DEBUG("allocating sections");

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

		LOG_DEBUG("allocated {} sections", SectionDirectory.size());
		return true;
	}

	void CopySections(sections::SectionDir& SectionDirectory, void* pImage)
	{
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
	}

	bool RunBasicRelocations(sections::SectionDir& SectionDirectory, PIMAGE_NT_HEADERS32 ntHeader)
	{
		LOG_DEBUG("starting standard relocations");

		const auto dataDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		const auto nRelocSize = dataDir.Size;
		const auto vaFirstReloc = dataDir.VirtualAddress;
		const auto pFirstReloc = sections::VAToLocalPtr<PIMAGE_BASE_RELOCATION>(SectionDirectory, vaFirstReloc);

		auto DebugRelocationCounter = 0;
		for (
			auto currentReloc = pFirstReloc;
			(uint32_t)currentReloc < (uint32_t)pFirstReloc + nRelocSize;
			currentReloc = (PIMAGE_BASE_RELOCATION)((uint32_t)currentReloc + currentReloc->SizeOfBlock)
			)
		{
			if (currentReloc->SizeOfBlock == 0)
			{
				break;
			}

			auto nRelocCount = (currentReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			auto vaRelocationBase = currentReloc->VirtualAddress;
			auto pRelocationItems = (uint16_t*)((uint32_t)currentReloc + sizeof(IMAGE_BASE_RELOCATION));

			for (auto i = 0; i < nRelocCount; i++)
			{
				const auto RelocationOffset = pRelocationItems[i] & 0xfff;
				const auto RelocationType = pRelocationItems[i] >> 12;

				if (RelocationType == IMAGE_REL_BASED_HIGHLOW)
				{
					auto vaRelocation = vaRelocationBase + RelocationOffset;
					auto pRelocation = sections::VAToLocalPtr<uint32_t*>(SectionDirectory, vaRelocation);

					if (!pRelocation)
					{
						LOG_ERROR("Could not resolve a relocation");
						return false;
					}

					auto vaRelocationTarget = *pRelocation - ntHeader->OptionalHeader.ImageBase;
					auto pRelocationTarget = sections::VAToRemotePtr<uint32_t>(SectionDirectory, vaRelocationTarget);

					if (!pRelocation)
					{
						LOG_ERROR("Could not resolve a relocation");
						return false;
					}

					*pRelocation = pRelocationTarget;
					DebugRelocationCounter++;
				}
				else if (RelocationType == IMAGE_REL_BASED_ABSOLUTE)
				{
					// ABS == we dont need to reloc it
				}
				else
				{
					LOG_ERROR("UNABLE TO RELOCATE ITEM: TYPE=0x{:04x}", RelocationType);
					return false;
				}
			}
		}

		LOG_DEBUG("finsihed {} standard relocations", DebugRelocationCounter);
		return true;
	}
	
	void RelReloc(sections::SectionDir& SectionDirectory, cs_insn& Instruction, uint32_t offset, sections::MappedSection& CurrentSection)
	{
		const uint32_t pAddress = Instruction.address;
		const uint32_t pNextInstruction = pAddress + Instruction.size;
		const uint32_t vaNextInstruction = sections::LocalToVAPtr<uint32_t>(SectionDirectory, pNextInstruction);

		const uint32_t relTarget = *(uint32_t*)(pAddress + offset);
		const uint32_t vaTarget = vaNextInstruction + relTarget;

		const uint32_t pRelocatedTarget = sections::VAToRemotePtr<uint32_t>(SectionDirectory, vaTarget);
		const uint32_t relRelocated = pRelocatedTarget - sections::VAToRemotePtr<uint32_t>(SectionDirectory, vaNextInstruction);

		if (relRelocated != relTarget)
		{
			LOG_TRACE("\tREL32 RELOC: {} {} \t va=0x{:08x} original=0x{:08x} new=0x{:08x}", Instruction.mnemonic, Instruction.op_str, vaNextInstruction - Instruction.size, relTarget, relRelocated);
			*(uint32_t*)(pAddress + offset) = relRelocated;
		}
	}

	bool RunRelRelocation(sections::SectionDir& SectionDirectory)
	{
		LOG_DEBUG("running inter-section relative relocations");
		for (auto& Section : SectionDirectory)
		{
			if (Section.Header().Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				disassembler::instructions Instrucitons;
				if (!disassembler::disassemble(Section.GetLocalAllocation(), Section.Header().SizeOfRawData, Instrucitons))
				{
					LOG_ERROR("disassembler failed!");
					return false;
				}

				for (auto& Instruction : Instrucitons)
				{
					if (
						(!strcmp(Instruction.mnemonic, "call") && Instruction.bytes[0] == 0xE8 /* CALL rel32; */) ||
						(!strcmp(Instruction.mnemonic, "jmp") && Instruction.bytes[0] == 0xE9 /* JMP rel32; */)
						)
					{
						RelReloc(SectionDirectory, Instruction, 1, Section);
					}
					else if (Instruction.bytes[0] == 0x0F) // https://c9x.me/x86/html/file_module_x86_id_146.html
					{
						// todo: not this ugly shit
						if (
							(!strcmp(Instruction.mnemonic, "jo") && Instruction.bytes[1] == 0x80) ||
							(!strcmp(Instruction.mnemonic, "jno") && Instruction.bytes[1] == 0x81) ||
							(!strcmp(Instruction.mnemonic, "jb") && Instruction.bytes[1] == 0x82) ||
							(!strcmp(Instruction.mnemonic, "jc") && Instruction.bytes[1] == 0x82) ||
							(!strcmp(Instruction.mnemonic, "jnae") && Instruction.bytes[1] == 0x82) ||
							(!strcmp(Instruction.mnemonic, "jae") && Instruction.bytes[1] == 0x83) ||
							(!strcmp(Instruction.mnemonic, "jnb") && Instruction.bytes[1] == 0x83) ||
							(!strcmp(Instruction.mnemonic, "jnc") && Instruction.bytes[1] == 0x83) ||
							(!strcmp(Instruction.mnemonic, "je") && Instruction.bytes[1] == 0x84) ||
							(!strcmp(Instruction.mnemonic, "jz") && Instruction.bytes[1] == 0x84) ||
							(!strcmp(Instruction.mnemonic, "jne") && Instruction.bytes[1] == 0x85) ||
							(!strcmp(Instruction.mnemonic, "jnz") && Instruction.bytes[1] == 0x85) ||
							(!strcmp(Instruction.mnemonic, "jbe") && Instruction.bytes[1] == 0x86) ||
							(!strcmp(Instruction.mnemonic, "jna") && Instruction.bytes[1] == 0x86) ||
							(!strcmp(Instruction.mnemonic, "ja") && Instruction.bytes[1] == 0x87) ||
							(!strcmp(Instruction.mnemonic, "jnbe") && Instruction.bytes[1] == 0x87) ||
							(!strcmp(Instruction.mnemonic, "js") && Instruction.bytes[1] == 0x88) ||
							(!strcmp(Instruction.mnemonic, "jns") && Instruction.bytes[1] == 0x89) ||
							(!strcmp(Instruction.mnemonic, "jp") && Instruction.bytes[1] == 0x8A) ||
							(!strcmp(Instruction.mnemonic, "jpe") && Instruction.bytes[1] == 0x8A) ||
							(!strcmp(Instruction.mnemonic, "jpp") && Instruction.bytes[1] == 0x8B) ||
							(!strcmp(Instruction.mnemonic, "jnp") && Instruction.bytes[1] == 0x8B) ||
							(!strcmp(Instruction.mnemonic, "jl") && Instruction.bytes[1] == 0x8C) ||
							(!strcmp(Instruction.mnemonic, "jnge") && Instruction.bytes[1] == 0x8C) ||
							(!strcmp(Instruction.mnemonic, "jge") && Instruction.bytes[1] == 0x8D) ||
							(!strcmp(Instruction.mnemonic, "jnl") && Instruction.bytes[1] == 0x8D) ||
							(!strcmp(Instruction.mnemonic, "jng") && Instruction.bytes[1] == 0x8E) ||
							(!strcmp(Instruction.mnemonic, "jle") && Instruction.bytes[1] == 0x8E) ||
							(!strcmp(Instruction.mnemonic, "jg") && Instruction.bytes[1] == 0x8F) ||
							(!strcmp(Instruction.mnemonic, "jnle") && Instruction.bytes[1] == 0x8F)
							)
						{
							RelReloc(SectionDirectory, Instruction, 2, Section);
						}
					}
				}
			}
		}
		LOG_DEBUG("finshed relative relocations");

		return true;
	}

	bool WriteSections(sections::SectionDir& SectionDirectory)
	{
		for (auto& Section : SectionDirectory)
		{
			Section.WriteSectionToRemote();
		}

		return true;
	}

	bool RunImports(PIMAGE_NT_HEADERS32 ntHeader, sections::SectionDir& SectionDirectory)
	{
		LOG_DEBUG("starting imports");
		auto vaImportDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		
		auto CurrentImportDesc = sections::VAToLocalPtr<PIMAGE_IMPORT_DESCRIPTOR>(SectionDirectory, vaImportDir);

		auto ImportCount = 0;

		while (CurrentImportDesc->FirstThunk)
		{

		}

		LOG_DEBUG("finished {} imports", ImportCount);
		return true;
	}

	bool MapImage(void* pImage, const size_t ImageSize, process::Process& Process)
	{
		LOG_DEBUG("starting map");

		// Verify this is a good image
		if (!VerifyImage(pImage, ImageSize))
		{
			return false;
		}

		// Grab our headers
		const auto dosHeader = PE::GetDOSHeaders(pImage);
		const auto ntHeader = PE::GetNTHeaders(pImage);

		sections::SectionDir SectionDirectory;
		if (!AllocateSections(SectionDirectory, ntHeader, Process))
		{
			LOG_ERROR("AllocateSections Failed!");
			return false;
		}

		CopySections(SectionDirectory, pImage);

		if (!RunBasicRelocations(SectionDirectory, ntHeader))
		{
			LOG_ERROR("RunBasicRelocations Failed!");
			return false;
		}

		if (!RunRelRelocation(SectionDirectory))
		{
			LOG_ERROR("RunBasicRelocations Failed!");
			return false;
		}

		if (!RunImports(ntHeader, SectionDirectory))
		{
			LOG_ERROR("RunImports Failed!");
			return false;
		}

		//typedef BOOL(__stdcall * DLLMain_Func)(HINSTANCE, DWORD, LPVOID);
		//DLLMain_Func EntryPoint = sections::VAToRemotePtr<DLLMain_Func>(SectionDirectory, ntHeader->OptionalHeader.AddressOfEntryPoint);
		//EntryPoint(0, DLL_PROCESS_ATTACH, 0);

		LOG_DEBUG("finished map");
		return true;
	}
}