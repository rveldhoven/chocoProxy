
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <map>

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "..\\chocoDLL\x64_hook.hpp"
#include "..\\chocoDLL\x86_hook.hpp"

#pragma comment (lib, "Ws2_32.lib")

const char* home_ip = "A1B2C3D4E5F6G7H8123123123123";
const char* home_port = "Z1Y2X3GHJKLMNOP";

#ifdef _WIN64
std::shared_ptr<cHookManager>		hook_manager = nullptr;
std::map<std::string, std::shared_ptr<cx64PrologueHook>> hook_library;
#else
std::shared_ptr<cx86HookManager> hook_manager = nullptr;
std::map<std::string, std::shared_ptr<cx86PrologueHook>> hook_library;
#endif

std::recursive_mutex		connection_list_mutex;
std::map<SOCKET, SOCKET>	connection_list;


std::recursive_mutex									recvfrom_packet_list;
std::map<SOCKET, std::vector<std::vector<uint8_t>>>		recvfrom_packets;


void wsa_init()
{
	WSADATA wsa_data = {};
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

void connect_home(SOCKET temp_socket, const std::string& ip, const uint16_t port)
{
	ADDRESS_FAMILY sin_fam = AF_INET;

	sockaddr_in server_address = {};
	sockaddr_in6 server_address6 = {};

	if (inet_pton(AF_INET, ip.c_str(), (void*)& server_address.sin_addr) <= 0)
	{
		if (inet_pton(AF_INET6, ip.c_str(), (void*)& server_address6.sin6_addr) <= 0)
		{
			throw std::runtime_error("Error: invalid IP");
		}

		sin_fam = AF_INET6;
	}

	server_address6.sin6_family = AF_INET6;
	server_address.sin_family = AF_INET;
	server_address6.sin6_port = htons(port);
	server_address.sin_port = htons(port);

	int connect_result = 0;

	if (sin_fam == AF_INET)
		connect_result = connect(temp_socket, (SOCKADDR*)& server_address, sizeof(server_address));
	else
		connect_result = connect(temp_socket, (SOCKADDR*)& server_address6, sizeof(server_address6));

	if (connect_result == SOCKET_ERROR)
		throw std::runtime_error("Error: failed to connect");
}

SOCKET connect_or_get_home_socket(SOCKET hooked_socket)
{
	{
		std::lock_guard<decltype(connection_list_mutex)> lock(connection_list_mutex);

		if (connection_list.find(hooked_socket) != connection_list.end())
			return connection_list[hooked_socket];
	}

	SOCKET new_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (new_socket == INVALID_SOCKET)
		return INVALID_SOCKET;

	try
	{
		connect_home(new_socket, home_ip, strtol(home_port, nullptr, 10));

		{
			std::lock_guard<decltype(connection_list_mutex)> lock(connection_list_mutex);

			connection_list[hooked_socket] = new_socket;
		}

		return new_socket;
	}
	catch (std::exception e)
	{
		return INVALID_SOCKET;
	}

	return INVALID_SOCKET;
}

void send_packet_home(SOCKET home_socket, const std::vector<uint8_t>& packet)
{
	uint32_t packet_size = packet.size();

	std::vector<uint8_t> real_packet = std::vector<uint8_t>();
	real_packet.insert(real_packet.begin(), (uint8_t*)& packet_size, (uint8_t*)& packet_size + sizeof(packet_size));
	real_packet.insert(real_packet.end(), packet.begin(), packet.end());

	send(home_socket, (const char*)real_packet.data(), packet.size(), 0);
}

size_t get_bytes_available(SOCKET home_socket)
{
	DWORD result = 0;
	ioctlsocket(home_socket, FIONREAD, &result);

	return result;
}

std::vector<uint8_t> receive_packet_from_home(SOCKET home_socket)
{
	uint8_t message_size[4] = {};
	recv(home_socket, (char*)&message_size[0], 4, 0);

	uint32_t size = *(uint32_t*)&message_size[0];

	std::vector<uint8_t> packet;
	packet.resize(size);

	recv(home_socket, (char*)packet.data(), packet.size(), 0);

	return packet;
}

std::vector<uint8_t> send_receive(SOCKET home_socket, const std::vector<uint8_t>& data)
{
	if (data.size() == 0)
		return std::vector<uint8_t>();
	
	std::vector<uint8_t> send_size_buffer;

	uint32_t send_size = data.size();

	send(home_socket, (char*)send_size_buffer.data(), send_size_buffer.size(), 0);
	send(home_socket, (char*)data.data(), data.size(), 0);

	bool is_done = true;
	std::vector<uint8_t> recv_size_buffer;
	std::vector<uint8_t> recv_buffer;

	do
	{
		recv_buffer.clear();
		recv_size_buffer.clear();

		is_done = true;

		recv_size_buffer.resize(sizeof(uint32_t));

		recv(home_socket, (char*)recv_size_buffer.data(), recv_size_buffer.size(), 0);

		uint32_t recv_size = *(uint32_t*)recv_size_buffer.data();

		if (recv_size == 0xffffffff)
		{
			is_done = false;
			continue;
		}

		recv_buffer.resize(recv_size);
		recv(home_socket, (char*)recv_buffer.data(), recv_buffer.size(), 0);
	} while (is_done == false);

	return recv_buffer;
}

typedef int(WSAAPI* tsendto)(
	SOCKET         s,
	const char* buf,
	int            len,
	int            flags,
	const sockaddr* to,
	int            tolen
	);

tsendto o_send_to = nullptr;

int WINAPI hooked_sendto(
	SOCKET         s,
	const char* buf,
	int            len,
	int            flags,
	const sockaddr* to,
	int            tolen
)
{
	SOCKET home_socket = connect_or_get_home_socket(s);

	if (o_send_to == nullptr)
		o_send_to = (tsendto)hook_library["sendto"]->hook_get_trampoline_end();

	std::vector<uint8_t> first_buffer;

	first_buffer.resize(len);

	memcpy((void*)first_buffer.data(), buf, len);

	std::vector<uint8_t> second_buffer = send_receive(s, first_buffer, false);

	if (second_buffer.size() > 0)
		return o_send_to(s, (char*)second_buffer.data(), second_buffer.size(), flags, to, tolen);
	else
		return o_send_to(s, buf, len, flags, to, tolen);
}

int WINAPI hooked_recvfrom(
	SOCKET   s,
	char*	 buf,
	int      len,
	int      flags,
	sockaddr* from,
	int* fromlen
)
{

}

void set_hook(const std::string& module, const std::string& function, void* to_location)
{
	HANDLE module_handle;

	module_handle = (HANDLE)GetModuleHandleA(module.c_str());

	if (module_handle == NULL)
		module_handle = (HANDLE)LoadLibraryA(module.c_str());

	if (module_handle == NULL)
		throw std::runtime_error("Error: failed to obtain module handle");

	FARPROC function_handle = GetProcAddress((HMODULE)module_handle, function.c_str());

	if (function_handle == NULL)
		throw std::runtime_error("Error: failed to obtain function handle");

#ifdef _WIN64
	hook_library[function] = hook_manager->set_hook_all((uint64_t)function_handle, (uint64_t)to_location, false);
#else
	hook_library[function] = hook_manager->set_hook_all((uint32_t)function_handle, (uint32_t)to_location, false);
#endif
}

void real_main()
{
	try
	{
		std::shared_ptr<CopyPatterns> patterns = std::make_shared<CopyPatterns>();

#ifdef _WIN64
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x40, 0x55}, 2));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x40, 0x53}, 2));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x48, 0x8b, 0xc4}, 3));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x4c, 0x8b, 0xdc}, 3));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x48, 0x83, 0xec}, 4));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x48, 0x89, 0x5c, 0x24}, 5));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x48, 0x89, 0x4c, 0x24}, 5));

		hook_manager = std::make_shared<cHookManager>(patterns);
#else
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x6a}, 2));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x40, 0x55}, 2));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x8b, 0xff}, 2));
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x4c, 0x8b, 0xdc}, 3));

		hook_manager = std::make_shared<cx86HookManager>(patterns);
#endif

		set_hook("ws2_32.dll", "sendto", (void*)hooked_sendto);
		set_hook("ws2_32.dll", "recvfrom", (void*)hooked_recvfrom);
	}
	catch (std::exception e)
	{
		MessageBoxA(NULL, e.what(), "Error", MB_OK);
	}
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)real_main, NULL, 0, NULL);

	return TRUE;
}