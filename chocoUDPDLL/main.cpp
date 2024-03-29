
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
std::map<SOCKET, bool>		connection_initialized_list;

void debug_warning(const std::string& message)
{
	std::string complete_warning = "Warning: " + message;

	MessageBoxA(NULL, complete_warning.c_str(), "Warning", MB_OK | MB_ICONWARNING);
}

void wsa_init()
{
	WSADATA wsa_data = {};
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

void connect_home_socket(SOCKET temp_socket, const std::string& ip, const uint16_t port)
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
		connect_home_socket(new_socket, home_ip, strtol(home_port, nullptr, 10));

		{
			std::lock_guard<decltype(connection_list_mutex)> lock(connection_list_mutex);

			connection_list[hooked_socket] = new_socket;
			connection_initialized_list[hooked_socket] = false;
		}

		return new_socket;
	}
	catch (std::exception e)
	{
		return INVALID_SOCKET;
	}

	return INVALID_SOCKET;
}

void close_home_socket(SOCKET hooked_socket)
{
	std::lock_guard<decltype(connection_list_mutex)> lock(connection_list_mutex);

	auto connection_list_it = connection_list.find(hooked_socket);
	auto connection_initialized_it = connection_initialized_list.find(hooked_socket);

	if (connection_list_it == connection_list.end())
		return;

	SOCKET closing_socket = connection_list_it->second;

	closesocket(closing_socket);

	connection_list.erase(hooked_socket);

	if (connection_initialized_it == connection_initialized_list.end())
		return;
	
	connection_initialized_list.erase(hooked_socket);
}

void send_only(SOCKET s, const std::vector<uint8_t>& data)
{
	std::vector<uint8_t> send_buffer = data;
	uint32_t send_size = data.size();

	send_buffer.insert(send_buffer.begin(), (uint8_t*)& send_size, (uint8_t*)& send_size + sizeof(send_size));

	if (send(s, (char*)send_buffer.data(), send_buffer.size(), 0) == SOCKET_ERROR)
		throw std::runtime_error("Error: socket closed");
}

size_t get_bytes_available(SOCKET s)
{
	u_long result = 0;

	if (ioctlsocket(s, FIONREAD, &result) == SOCKET_ERROR)
		throw std::runtime_error("Error: FIONREAD call failed");

	return result;
}

std::vector<uint8_t> receive_only(SOCKET s)
{
	std::vector<uint8_t> message_size_buffer;
	std::vector<uint8_t> message_bytes_buffer;

	message_size_buffer.resize(sizeof(uint32_t));

	size_t bytes_peeked = recv(s, (char*)message_size_buffer.data(), message_size_buffer.size(), MSG_PEEK);

	if (bytes_peeked != 4)
		throw std::runtime_error("Error: could not peek message size from socket");

	size_t bytes_read = recv(s, (char*)message_size_buffer.data(), message_size_buffer.size(), 0);

	if (bytes_read != bytes_peeked)
		throw std::runtime_error("Error: could not read message size from socket");

	uint32_t message_size = *(uint32_t*)message_size_buffer.data();

	message_bytes_buffer.reserve(message_size);

	const size_t chunk_size = 8096;

	char chunk_buffer[chunk_size] = {};
	size_t num_reads = message_size / chunk_size;
	size_t last_read = message_size % chunk_size;

	for (size_t i = 0; i < num_reads; i++)
	{
		size_t chunk_read_size = recv(s, (char*)chunk_buffer[0], chunk_size, 0);

		if (chunk_read_size == SOCKET_ERROR)
			throw std::runtime_error("Error: could not read chunk from socket: " + std::to_string(WSAGetLastError()));

		if (chunk_read_size != chunk_size)
			throw std::runtime_error("Error: could not read chunk from socket");

		message_bytes_buffer.insert(message_bytes_buffer.end(), &chunk_buffer[0], &chunk_buffer[0] + chunk_size);
	}

	if (last_read > 0)
	{
		size_t last_read_size = recv(s, (char*)chunk_buffer[0], last_read, 0);

		if (last_read_size == SOCKET_ERROR)
			throw std::runtime_error("Error: could not read last chunk from socket: " + std::to_string(WSAGetLastError()));

		if (last_read_size != last_read)
			throw std::runtime_error("Error: could not read last chunk from socket: " + std::to_string(last_read_size) + " != " + std::to_string(last_read));

		message_bytes_buffer.insert(message_bytes_buffer.end(), &chunk_buffer[0], &chunk_buffer[0] + last_read);
	}

	return message_bytes_buffer;
}

std::vector<uint8_t> send_receive(SOCKET home_socket, const std::vector<uint8_t>& data)
{
	if (data.size() == 0)
		return std::vector<uint8_t>();
	
	send_only(home_socket, data);

	std::vector<uint8_t> result = receive_only(home_socket);
	
	return result;
}

#define request_mode_write 1
#define request_mode_read 2

#pragma pack(push, 1)
struct UDPRequest
{
	uint8_t		mode;			// 0
	uint32_t	src_ip;			// 1	
	uint16_t	src_port;		// 5
	uint32_t	dst_ip;			// 7
	uint16_t	dst_port;		// 11
};
#pragma pack(pop)

bool is_state_initialized(SOCKET s)
{
	{
		std::lock_guard<decltype(connection_list_mutex)> lock(connection_list_mutex);

		if (connection_list.find(s) != connection_list.end())
			return connection_initialized_list[s];
	}

	return true;
}

void set_state_initialized(SOCKET s)
{
	{
		std::lock_guard<decltype(connection_list_mutex)> lock(connection_list_mutex);

		if (connection_list.find(s) != connection_list.end())
			connection_initialized_list[s] = true;
	}
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

	if (home_socket == INVALID_SOCKET)
		return SOCKET_ERROR;

	if (o_send_to == nullptr)
		o_send_to = (tsendto)hook_library["sendto"]->hook_get_trampoline_end();

	if (is_state_initialized(s) == false)
	{
		set_state_initialized(s);

		UDPRequest state_id_update = {};
		state_id_update.mode = request_mode_write;

		sockaddr_in sin;
		int addrlen = sizeof(sin);

		if (getsockname(s, (struct sockaddr*) & sin, &addrlen) == 0 && sin.sin_family == AF_INET && addrlen == sizeof(sin))
		{
			state_id_update.src_ip = sin.sin_addr.S_un.S_addr;
			state_id_update.src_port = sin.sin_port;
		}
		else
		{
			state_id_update.src_ip = -1;
			state_id_update.src_port = -1;
		}

		state_id_update.dst_ip = ((SOCKADDR_IN*)to)->sin_addr.S_un.S_addr;
		state_id_update.dst_port = ((SOCKADDR_IN*)to)->sin_port;

		std::vector<uint8_t> first_send_data((uint8_t*)& state_id_update, (uint8_t*)& state_id_update + sizeof(state_id_update));

		try
		{
			send_only(home_socket, first_send_data);
		}
		catch (std::exception e)
		{
			debug_warning(e.what());
			close_home_socket(s);
		}
	}

	std::vector<uint8_t> first_buffer;

	first_buffer.resize(len);

	memcpy((void*)first_buffer.data(), buf, len);

	UDPRequest request = {};
	request.mode = request_mode_write;

	sockaddr_in sin;
	int addrlen = sizeof(sin);

	if (getsockname(s, (struct sockaddr*) & sin, &addrlen) == 0 && sin.sin_family == AF_INET && addrlen == sizeof(sin))
	{
		request.src_ip = sin.sin_addr.S_un.S_addr;
		request.src_port = sin.sin_port;
	}
	else
	{
		request.src_ip = -1;
		request.src_port = -1;
	}

	request.dst_ip = ((SOCKADDR_IN*)to)->sin_addr.S_un.S_addr;
	request.dst_port = ((SOCKADDR_IN*)to)->sin_port;
	first_buffer.insert(first_buffer.begin(), (uint8_t*)& request, (uint8_t*)& request + sizeof(request));

	std::vector<uint8_t> second_buffer;

	try
	{
		second_buffer = send_receive(home_socket, first_buffer);
	}
	catch (std::exception e)
	{
		debug_warning(e.what());
		close_home_socket(s);
	}

	int sendto_result = 0;
	
	if (second_buffer.size() > 0)
		sendto_result = o_send_to(s, (char*)second_buffer.data(), second_buffer.size(), flags, to, tolen);
	else
		sendto_result = o_send_to(s, buf, len, flags, to, tolen);

	if (sendto_result == SOCKET_ERROR)
	{
		debug_warning("Sendto reported error");
		close_home_socket(s);
	}

	return sendto_result;
}

typedef int(WSAAPI* trecvfrom)(
	SOCKET   s,
	char* buf,
	int      len,
	int      flags,
	sockaddr* from,
	int* fromlen
	);

trecvfrom o_recv_from = nullptr;

int WINAPI hooked_recvfrom(
	SOCKET   s,
	char* buf,
	int      len,
	int      flags,
	sockaddr* from,
	int* fromlen
)
{
	SOCKET home_socket = connect_or_get_home_socket(s);
	
	if (o_recv_from == nullptr)
		o_recv_from = (trecvfrom)hook_library["recvfrom"]->hook_get_trampoline_end();
	
	auto result = o_recv_from(s, buf, len, flags, from, fromlen);

	if (result == SOCKET_ERROR)
	{
		debug_warning("Recvfrom reported error");

		close_home_socket(s);

		return result;
	}

	if (is_state_initialized(s) == false)
	{
		set_state_initialized(s);

		UDPRequest state_id_update = {};
		state_id_update.mode = request_mode_write;

		sockaddr_in sin;
		int addrlen = sizeof(sin);

		if (getsockname(s, (struct sockaddr*) & sin, &addrlen) == 0 && sin.sin_family == AF_INET && addrlen == sizeof(sin))
		{
			state_id_update.dst_ip = sin.sin_addr.S_un.S_addr;
			state_id_update.dst_port = sin.sin_port;
		}
		else
		{
			state_id_update.dst_ip = -1;
			state_id_update.dst_port = -1;
		}

		state_id_update.src_ip = ((SOCKADDR_IN*)from)->sin_addr.S_un.S_addr;
		state_id_update.src_port = ((SOCKADDR_IN*)from)->sin_port;

		std::vector<uint8_t> first_send_data((uint8_t*)& state_id_update, (uint8_t*)& state_id_update + sizeof(state_id_update));

		try
		{
			send_only(home_socket, first_send_data);
		}
		catch (std::exception e)
		{
			debug_warning(e.what());
			close_home_socket(s);
		}
	}

	std::vector<uint8_t> first_buffer;

	first_buffer.resize(result);

	memcpy((void*)first_buffer.data(), buf, result);

	sockaddr_in sin;
	int addrlen = sizeof(sin);

	UDPRequest request = {};
	request.mode = request_mode_read;

	if (getsockname(s, (struct sockaddr*) & sin, &addrlen) == 0 && sin.sin_family == AF_INET && addrlen == sizeof(sin))
	{
		request.dst_ip = sin.sin_addr.S_un.S_addr;
		request.dst_ip = sin.sin_port;
	}
	else
	{
		request.dst_ip = -1;
		request.dst_ip = -1;
	}
	
	request.src_ip = ((SOCKADDR_IN*)from)->sin_addr.S_un.S_addr;
	request.src_port = ((SOCKADDR_IN*)from)->sin_port;

	first_buffer.insert(first_buffer.begin(), (uint8_t*)& request, (uint8_t*)& request + sizeof(request));

	std::vector<uint8_t> second_buffer;

	try
	{
		second_buffer = send_receive(home_socket, first_buffer);
	}
	catch (std::exception e)
	{
		debug_warning(e.what());
		close_home_socket(s);
	}

	if (second_buffer.size() > len)
	{
		MessageBoxA(NULL, "Error: Dangerous packet modification: returned packet is too big for client buffer", "Error", MB_OK | MB_ICONERROR);
		return result;
	}

	memcpy(buf, second_buffer.data(), second_buffer.size());

	return second_buffer.size();
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
		patterns->insert(std::make_pair(std::vector<uint8_t>{0x40, 0x57}, 2));
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
		MessageBoxA(NULL, e.what(), "Error", MB_OK | MB_ICONERROR);
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