
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

void wsa_init()
{
	WSADATA wsa_data = {};
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

typedef int (WSAAPI *tconnect)(
	SOCKET         s,
	const sockaddr *name,
	int            namelen
);

tconnect o_connect = nullptr;

void connect_home(SOCKET temp_socket, const std::string& ip, const uint16_t port)
{
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

	if (o_connect == nullptr)
		o_connect = (tconnect)hook_library["connect"]->hook_get_trampoline_end();


	if (sin_fam == AF_INET)
		connect_result = o_connect(temp_socket, (SOCKADDR *)&server_address, sizeof(server_address));
	else
		connect_result = o_connect(temp_socket, (SOCKADDR *)&server_address6, sizeof(server_address6));

	if (connect_result == SOCKET_ERROR)
		throw std::runtime_error("Error: failed to connect");
}

struct SOCKS4Request
{
	uint8_t socks_version;
	uint8_t socks_command;
	uint16_t socks_port;
	uint32_t socks_ip;
};

struct SOCKS4Response
{
	uint8_t socks_version;
	uint8_t socks_result;
	uint16_t socks_port;
	uint32_t socks_ip;
};

int WSAAPI hooked_connect(
	SOCKET         s,
	const sockaddr *name,
	int            namelen
)
{
	try
	{
		connect_home(s, home_ip, strtol(home_port, nullptr, 10));
	}
	catch (...)
	{
		return SOCKET_ERROR;
	}

	SOCKS4Request request = {};
	request.socks_version = 4;
	request.socks_command = 1;
	request.socks_port = ((SOCKADDR_IN*)name)->sin_port;
	request.socks_ip = ((SOCKADDR_IN*)name)->sin_addr.S_un.S_addr;

	uint8_t dummy = 0;

	if (send(s, (const char*)&request, sizeof(request), 0) == SOCKET_ERROR)
		return SOCKET_ERROR;

	if (send(s, (const char*)&dummy, 1, 0) == SOCKET_ERROR)
		return SOCKET_ERROR;

	SOCKS4Response response = {};

	if (recv(s, (char*)&response, sizeof(response), 0) == SOCKET_ERROR)
		return SOCKET_ERROR;

	if (response.socks_result == 91)
	{
		return SOCKET_ERROR;
	}

	return 0;
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

		set_hook("ws2_32.dll", "connect", (void*)hooked_connect);
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