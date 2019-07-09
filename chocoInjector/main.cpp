
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <fstream>

#include <ctime>

#include <Windows.h>

const char* home_ip_signature = "A1B2C3D4E5F6G7H8123123123123";
const char* home_port_signature = "Z1Y2X3GHJKLMNOP";
const char* hook_function_signature = "zscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhn";

std::vector<uint8_t> read_file_from_disk(const std::string& filename)
{
	std::fstream f(filename, std::ios::binary | std::ios::in);

	if (f.good() == false)
		return std::vector<uint8_t>();

	f.seekg(0, SEEK_END);
	size_t length = f.tellg();
	f.seekg(0, SEEK_SET);

	std::vector<uint8_t> result;
	result.resize(length);
	f.read((char*)result.data(), result.size());

	return result;
}

void write_file_to_disk(const std::string& filename, const std::vector<uint8_t>& file_bytes)
{
	std::fstream f(filename, std::ios::binary | std::ios::out);

	if (f.good() == false)
		return;

	f.write((char*)file_bytes.data(), file_bytes.size());
}

std::string get_temp_dll_file()
{
	char buffer[MAX_PATH];

	GetEnvironmentVariableA("temp", buffer, MAX_PATH);

	std::string result = buffer;
	
	if (result[result.size() - 1] != '\\')
		result += "\\";

	srand(time(NULL));

	std::string alp = "abceijiejfijsfsijes";

	for (int i = 0; i < 20; i++)
		result += alp[rand() % alp.size()];

	result += ".dll";

	return result;
}

std::vector<uint8_t> replace_all(const std::vector<uint8_t>& source, const std::vector<uint8_t>& replace_what, const std::vector<uint8_t> replace_with, bool use_padding = true)
{
	std::vector<uint8_t> result_vector;

	for (size_t i = 0; i < source.size(); i++)
	{
		if (i + replace_what.size() < source.size())
		{
			if (memcmp(&source[i], &replace_what[0], replace_what.size()) == 0)
			{
				result_vector.insert(result_vector.end(), replace_with.begin(), replace_with.end());

				i += replace_what.size();

				if (use_padding == true)
					for (size_t x = 0; x < replace_what.size() - replace_with.size() + 1; x++)
						result_vector.push_back(0);
			}
			else
			{
				result_vector.push_back(source[i]);
			}
		}
		else
			result_vector.push_back(source[i]);
	}


	return result_vector;
}

std::string create_modified_dll(const std::string& str_dll_path, std::string ip, std::string port, const std::string& function)
{
	auto dll_file = read_file_from_disk(str_dll_path);

	if (dll_file.size() == 0)
		return "";

	std::vector<uint8_t> replace_ip(ip.begin(), ip.end());
	replace_ip.push_back(0);

	std::vector<uint8_t> replace_port(port.begin(), port.end());
	replace_port.push_back(0);

	std::vector<uint8_t> replace_function(function.begin(), function.end());
	replace_function.push_back(0);
	replace_function.push_back(0);

	std::string str_home_ip_signature = home_ip_signature;
	std::string str_home_port_signature = home_port_signature;
	std::string str_function_signature = hook_function_signature;

	std::vector<uint8_t> replace_signature_ip(str_home_ip_signature.begin(), str_home_ip_signature.end());
	std::vector<uint8_t> replace_signature_port(str_home_port_signature.begin(), str_home_port_signature.end());
	std::vector<uint8_t> replace_signature_function = {};

	if(function != "connect")
		replace_signature_function = std::vector<uint8_t>(str_function_signature.begin(), str_function_signature.end());

	auto config_one = replace_all(dll_file, replace_signature_ip, replace_ip);
	auto config_two = replace_all(config_one, replace_signature_port, replace_port);
	std::vector<uint8_t> config_three = {};

	if (function != "connect")
		config_three = replace_all(config_two, replace_signature_function, replace_function);
	else
		config_three = config_two;

	std::string filename = get_temp_dll_file();

	write_file_to_disk(filename, config_three);

	return filename;
}

int main(int argc, char** argv)
{
	std::string str_pid = argv[1];
	std::string str_dll_path = argv[2];
	std::string ip = argv[3];
	std::string port = argv[4];
	std::string function = argv[5];

	std::cout << "Injecting: '" << str_dll_path << "' into: PID: '" << str_pid << "'" << std::endl;
	std::cout << "chocoDLL client will connect to: " << ip << ":" << port << std::endl;
	std::cout << "Socket function hooked: " << function << std::endl;

	std::string real_dll_file = create_modified_dll(str_dll_path, ip, port, function);

	uint32_t pid = atoi(str_pid.c_str());

	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (process_handle == (HANDLE)-1 || process_handle == NULL)
	{
		std::cout << "Error: failed to open proccess" << std::endl;
		return 0;
	}

	void* load_library_address = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	void* remote_dll_name = VirtualAllocEx(process_handle, NULL, real_dll_file.size() + 1, MEM_COMMIT | MEM_RESERVE, 0x40);

	if(remote_dll_name == NULL)	
	{
		std::cout << "Error: failed to allocate memory" << std::endl;
	}

	SIZE_T bytes_written = 0;

	WriteProcessMemory(process_handle, (void*)remote_dll_name, real_dll_file.data(), real_dll_file.size(), &bytes_written);

	CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_address, (void*)remote_dll_name, 0, NULL);

	return 0;
}