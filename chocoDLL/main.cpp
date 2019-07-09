
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <map>

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "x64_hook.hpp"
#include "x86_hook.hpp"

#pragma comment (lib, "Ws2_32.lib")

std::recursive_mutex home_sockets_mutex;
std::map<SOCKET, SOCKET> home_sockets;

const char* home_ip = "A1B2C3D4E5F6G7H8123123123123";
const char* home_port = "Z1Y2X3GHJKLMNOP";
char* hook_function = (char*)"zscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhnzscfbhn";

#ifdef _WIN64
std::shared_ptr<cHookManager>		hook_manager = nullptr;
std::map<std::string, std::shared_ptr<cx64PrologueHook>> hook_library;
#else
std::shared_ptr<cx86HookManager> hook_manager = nullptr;
std::map<std::string, std::shared_ptr<cx86PrologueHook>> hook_library;
#endif

std::vector<uint8_t> send_receive(SOCKET linked_socket, const std::vector<uint8_t>& data, bool is_send_hook);

void wsa_init()
{
	WSADATA wsa_data = {};
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

typedef int
(WSAAPI
*tclosesocket)(
	_In_ SOCKET s
	);

tclosesocket o_close_socket = nullptr;

int WSAAPI hooked_closesocket(
_In_ SOCKET s
)
{
	if(o_close_socket == nullptr)
		o_close_socket = (tclosesocket)hook_library["closesocket"]->hook_get_trampoline_end();

	std::lock_guard<decltype(home_sockets_mutex)> lock(home_sockets_mutex);

	if (home_sockets.find(s) != home_sockets.end())
	{
		o_close_socket(home_sockets[s]);

		home_sockets.erase(s);
	}

	return o_close_socket(s);
}

void connect_home(SOCKET linked_socket, const std::string& ip, const uint16_t port)
{
	std::lock_guard<decltype(home_sockets_mutex)> lock(home_sockets_mutex);

	SOCKET temp_socket;

	temp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	ADDRESS_FAMILY sin_fam = AF_INET;

	sockaddr_in server_address = {};
	sockaddr_in6 server_address6 = {};

	if (inet_pton(AF_INET, ip.c_str(), (void*)&server_address.sin_addr) <= 0)
	{
		if (inet_pton(AF_INET6, ip.c_str(), (void*)&server_address6.sin6_addr) <= 0)
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

	if(sin_fam == AF_INET)
		connect_result = connect(temp_socket, (SOCKADDR *)&server_address, sizeof(server_address));
	else
		connect_result = connect(temp_socket, (SOCKADDR *)&server_address6, sizeof(server_address6));

	if (connect_result == SOCKET_ERROR)
		throw std::runtime_error("Error: failed to connect");

	home_sockets[linked_socket] = temp_socket;
}

typedef int (WSAAPI *tsend)(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
	);

tsend o_send = nullptr;

int WSAAPI send_hook(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
)
{
	if(o_send == nullptr)
		o_send = (tsend)hook_library["send"]->hook_get_trampoline_end();

	std::vector<uint8_t> first_buffer;

	first_buffer.resize(len);

	memcpy((void*)first_buffer.data(), buf, len);

	std::vector<uint8_t> second_buffer = send_receive(s, first_buffer, true);

	if (second_buffer.size() > 0)
		return o_send(s, (char*)second_buffer.data(), second_buffer.size(), flags);
	else
		return o_send(s, buf, len, flags);
}

typedef int(WSAAPI *tsendto)(
	SOCKET         s,
	const char     *buf,
	int            len,
	int            flags,
	const sockaddr *to,
	int            tolen
	);

tsendto o_send_to = nullptr;

int WSAAPI sendto_hook(
	SOCKET         s,
	const char     *buf,
	int            len,
	int            flags,
	const sockaddr *to,
	int            tolen
)
{
	if(o_send_to == nullptr)
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

std::vector<uint8_t> send_receive(SOCKET linked_socket, const std::vector<uint8_t>& data, bool is_send_hook)
{
	std::lock_guard<decltype(home_sockets_mutex)> lock(home_sockets_mutex);

	if (data.size() == 0)
		return std::vector<uint8_t>();

	if (home_sockets.find(linked_socket) == home_sockets.end())
	{
		std::string str_home_ip = home_ip;
		uint16_t uint_home_port = atoi(home_port);

		connect_home(linked_socket, str_home_ip, uint_home_port);
	}

	SOCKET home_socket = home_sockets[linked_socket];

	std::vector<uint8_t> send_size_buffer;

	uint32_t send_size = data.size();

	send_size_buffer.insert(send_size_buffer.end(), (uint8_t*)&send_size, (uint8_t*)&send_size + sizeof(send_size));

	if (is_send_hook == true)
	{
		o_send(home_socket, (char*)send_size_buffer.data(), send_size_buffer.size(), 0);
		o_send(home_socket, (char*)data.data(), data.size(), 0);
	}
	else
	{
		send(home_socket, (char*)send_size_buffer.data(), send_size_buffer.size(), 0);
		send(home_socket, (char*)data.data(), data.size(), 0);
	}

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
	}
	while(is_done == false);

	return recv_buffer;
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

		set_hook("ws2_32.dll", "closesocket", (void*)hooked_closesocket);

		char* hooked_function = (char*)((char*)hook_function);
		
		if (strcmp(hooked_function, "sendto") == 0)
		{
			set_hook("ws2_32.dll", "sendto", (void*)sendto_hook);

			MessageBoxA(NULL, "sendto hook set", "hook", MB_OK);
		}
		else if (strcmp(hooked_function, "send") == 0)
		{
			set_hook("ws2_32.dll", "send", (void*)send_hook);

			MessageBoxA(NULL, "send hook set", "hook", MB_OK);
		}
		else
			throw std::runtime_error("Error: invalid hook function specified: '" + std::string(hooked_function) + "'");
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