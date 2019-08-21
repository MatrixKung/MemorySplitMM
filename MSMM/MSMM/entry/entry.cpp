#include <pch.h>

int main(int argc, char** argv)
{
	std::cout << argc;
	if (argc != 3)
	{
		std::cout << "please execute in following format:\n \tMSMM.exe <BINARY_PATH> <TARGET_APP_NAME>" << std::endl;
		std::cin.get();
		return 0;
	}

	const char* Binary_Path = argv[1];
	const char* Target_App_Name = argv[2];

	// load binary
	std::ifstream BinaryFile = std::ifstream(Binary_Path, std::ios::binary);

	if (!BinaryFile.is_open())
	{
		std::cout << "Could not open file " << Binary_Path << std::endl;
		std::cin.get();
		return 0;
	}

	const auto LoadedBinary = std::vector<char>(
		std::istreambuf_iterator<char>(BinaryFile),
		std::istreambuf_iterator<char>()
	);

	if (LoadedBinary.size() == 0)
	{
		std::cout << "Binary file was empty!" << std::endl;
		std::cin.get();
		return 0;
	}

	std::cin.get();
	return 0;
}