#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <fstream>
#include <iostream>
#include <thread>

#include <WinSock2.h>
#include <windows.h>

#pragma comment (lib, "Ws2_32.lib")

std::vector<uint8_t> recv_data(SOCKET client_socket)
{
	char recv_size[sizeof(uint32_t)];

	recv(client_socket, (char*)&recv_size[0], sizeof(uint32_t), 0);

	uint32_t real_recv_size = *(uint32_t*)&recv_size[0];

	std::vector<uint8_t> read_data;

	read_data.resize(real_recv_size);

	recv(client_socket, (char*)read_data.data(), read_data.size(), 0);

	return read_data;
}

void send_data(SOCKET client_socket, const std::vector<uint8_t>& data)
{
	std::vector<uint8_t> send_size_buffer;

	uint32_t send_size = data.size();

	send_size_buffer.insert(send_size_buffer.end(), (uint8_t*)&send_size, (uint8_t*)&send_size + sizeof(send_size));

	auto result_one = send(client_socket, (char*)send_size_buffer.data(), send_size_buffer.size(), 0);
	auto result_two = send(client_socket, (char*)data.data(), data.size(), 0);

	if (result_one == SOCKET_ERROR || result_two == SOCKET_ERROR)
		throw std::runtime_error("Error: send failed");
}

std::fstream output_stream("C:\\Users\\SCHiM\\AppData\\Local\\Temp\\aoe_stream.bin", std::ios::binary | std::ios::out);
std::fstream output_stream_two("C:\\Users\\SCHiM\\AppData\\Local\\Temp\\aoe_stream_modified.bin", std::ios::binary | std::ios::out);

void save_data(const std::vector<uint8_t>& data)
{
	if (output_stream.good() == false)
		throw std::runtime_error("Error: failed to open output stream");

	output_stream.write((char*)data.data(), data.size());
}

void save_data_modified(const std::vector<uint8_t>& data)
{
	if (output_stream_two.good() == false)
		throw std::runtime_error("Error: failed to open output stream");

	output_stream_two.write((char*)data.data(), data.size());
}

void replace_pattern(std::vector<uint8_t>& buffer, const std::vector<uint8_t> from, std::vector<uint8_t> to)
{
	for (uint32_t i = 0; i < buffer.size() - from.size(); i++)
	{
		if (memcmp(&buffer[i], &from[0], from.size()) != 0)
			continue;

		uint32_t offset = i;

		buffer.erase(buffer.begin() + offset, buffer.begin() + offset + from.size());
		buffer.insert(buffer.begin() + offset, to.begin(), to.end());
	}
}

std::string replace_string_to = "sum_map.exe";

void handle_client(SOCKET client_socket)
{
	std::string replace_string = "sum_map.rms";
	

	std::vector<uint8_t> replace_target_bytes(replace_string.begin(), replace_string.end());



	try
	{
		while (true)
		{
			auto read_data = recv_data(client_socket);

			save_data(read_data);

			std::vector<uint8_t> replace_to_bytes(replace_string_to.begin(), replace_string_to.end());

			replace_pattern(read_data, replace_target_bytes, replace_to_bytes);

			save_data_modified(read_data);

			send_data(client_socket, read_data);
		}
	} 
	catch (std::exception e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
	}
}

void menu_function()
{
	while (true)
	{
		std::cout << "New file name: ";

		std::string line = "";
		std::getline(std::cin, line);

		std::cout << "Setting new extension to: " << line << std::endl;
		replace_string_to = line;
	}
}

int main(int argc, char** argv)
{
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_addr("127.0.0.1");
	service.sin_port = htons(3456);

	// Create a SOCKET for connecting to server
	ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, (SOCKADDR *)&service, sizeof(service));
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// No longer need server socket
	closesocket(ListenSocket);

	std::thread(&menu_function).detach();

	handle_client(ClientSocket);
	   
	WSACleanup();

	return 0;
}