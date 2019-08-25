#include <pch.h>
#include <Windows.h>

int main(int argc, char** argv)
{
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

	std::vector<char> LoadedBinary;
	LoadedBinary.assign(
		std::istreambuf_iterator<char>(BinaryFile),
		std::istreambuf_iterator<char>()
	);

	if (LoadedBinary.size() == 0)
	{
		std::cout << "Binary file was empty!" << std::endl;
		std::cin.get();
		return 0;
	}

	if (libMSMM::MapImage((void*)LoadedBinary.data(), LoadedBinary.size(), Target_App_Name))
	{
		std::cout << "Successfully injected binary!" << std::endl;
	}
	else
	{
		std::cout << "Injection failed" << std::endl;
	}

	while (true)
	{
		Sleep(1000);
	}
	return 0;
}