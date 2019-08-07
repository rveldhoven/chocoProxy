#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <string>
#include <vector>
#include <iostream>

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment (lib, "Ws2_32.lib")

int client_main()
{
	std::cout << "Client main" << std::endl;

	int iResult;
	WSADATA wsaData;

	SOCKET SendSocket = INVALID_SOCKET;
	sockaddr_in RecvAddr;
	sockaddr_in server_addr;

	unsigned short Port = 27015;

	char SendBuf[1024];
	int BufLen = 1024;

	strcpy(SendBuf, "This is a test");



	//----------------------
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	//---------------------------------------------
	// Create a socket for sending data
	SendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SendSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//---------------------------------------------
	// Set up the RecvAddr structure with the IP address of
	// the receiver (in this example case "192.168.1.1")
	// and the specified port number.
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(Port);
	RecvAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	while (true)
	{
		std::cout << "My pid is: " << GetCurrentProcessId() << std::endl;
		std::cout << "Waiting for inject, press enter" << std::endl;
		system("pause");

		//---------------------------------------------
		// Send a datagram to the receiver
		wprintf(L"Sending a datagram to the receiver...\n");
		iResult = sendto(SendSocket,
			SendBuf, BufLen, 0, (SOCKADDR*)& RecvAddr, sizeof(RecvAddr));
		if (iResult == SOCKET_ERROR) {
			wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
			closesocket(SendSocket);
			WSACleanup();
			return 1;
		}

		char recvbuf[1024];

		int size = sizeof(server_addr);
		recvfrom(SendSocket, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)& server_addr, &size);

		std::cout << "Received: " << (char*)& recvbuf[0] << std::endl;
	}
	//---------------------------------------------
	// When the application is finished sending, close the socket.
	wprintf(L"Finished sending. Closing socket.\n");
	iResult = closesocket(SendSocket);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//---------------------------------------------
	// Clean up and quit.
	wprintf(L"Exiting.\n");
	WSACleanup();
	return 0;

}

int server_main()
{
	std::cout << "Server main" << std::endl;

	int iResult = 0;

	WSADATA wsaData;

	SOCKET RecvSocket;
	sockaddr_in RecvAddr;

	unsigned short Port = 27015;

	char RecvBuf[1024];
	int BufLen = 1024;

	sockaddr_in SenderAddr;
	int SenderAddrSize = sizeof(SenderAddr);

	//-----------------------------------------------
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error %d\n", iResult);
		return 1;
	}
	//-----------------------------------------------
	// Create a receiver socket to receive datagrams
	RecvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (RecvSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error %d\n", WSAGetLastError());
		return 1;
	}
	//-----------------------------------------------
	// Bind the socket to any address and the specified port.
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(Port);
	RecvAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	iResult = bind(RecvSocket, (SOCKADDR*)& RecvAddr, sizeof(RecvAddr));
	if (iResult != 0) {
		wprintf(L"bind failed with error %d\n", WSAGetLastError());
		return 1;
	}
	while (true)
	{
		//-----------------------------------------------
		// Call the recvfrom function to receive datagrams
		// on the bound socket.
		wprintf(L"Receiving datagrams...\n");
		iResult = recvfrom(RecvSocket,
			RecvBuf, BufLen, 0, (SOCKADDR*)& SenderAddr, &SenderAddrSize);
		if (iResult == SOCKET_ERROR) {
			wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
		}

		sendto(RecvSocket, RecvBuf, BufLen, 0, (SOCKADDR*)& SenderAddr, SenderAddrSize);
	}
	//-----------------------------------------------
	// Close the socket when finished receiving datagrams
	wprintf(L"Finished receiving. Closing socket.\n");
	iResult = closesocket(RecvSocket);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"closesocket failed with error %d\n", WSAGetLastError());
		return 1;
	}

	//-----------------------------------------------
	// Clean up and exit.
	wprintf(L"Exiting.\n");
	WSACleanup();
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		client_main();
	}
	else
	{
		server_main();
	}

	return 0;
}