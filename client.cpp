#define WIN32_LEAN_AND_MEAN
#include "common.h" // Включает winsock2.h, windows.h, ws2tcpip.h, string, итд.

#include <iostream>
#include <thread> 
#include <string>
#include <vector>
#include <atomic>  
#include <mutex>   
#include <lmcons.h> // Для UNLEN 
#include <stdio.h>  // Для _popen, _pclose, FILE
#include <chrono>   // Для std::chrono::milliseconds

// --- Глобальные переменные для управления интерактивной оболочкой ---
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;
HANDLE g_hChildProcess = NULL;
std::atomic<bool> g_isShellActive(false);
std::string g_currentShellType; 
std::mutex g_shellMutex; 

void SendClientInfo(SOCKET sock) {
    Message msg;
    ZeroMemory(&msg, sizeof(Message));
    msg.type = MessageType::INIT;
    
    char hostname[128];
    DWORD hostname_len = sizeof(hostname);
    if (!GetComputerNameA(hostname, &hostname_len)) {
        strncpy_s(msg.clientInfo.hostname, "UnknownHost", sizeof(msg.clientInfo.hostname) -1);
    } else {
        strncpy_s(msg.clientInfo.hostname, hostname, sizeof(msg.clientInfo.hostname) - 1);
    }
    msg.clientInfo.hostname[sizeof(msg.clientInfo.hostname)-1] = '\0';

    char username[UNLEN + 1]; 
    DWORD username_len = UNLEN + 1;
    if (!GetUserNameA(username, &username_len)) {
        strncpy_s(msg.clientInfo.username, "UnknownUser", sizeof(msg.clientInfo.username) - 1);
    } else {
        strncpy_s(msg.clientInfo.username, username, sizeof(msg.clientInfo.username) - 1);
    }
    msg.clientInfo.username[sizeof(msg.clientInfo.username)-1] = '\0';

    if (send(sock, (char*)&msg, sizeof(Message), 0) == SOCKET_ERROR) {
         std::cerr << "[Client] Failed to send client info. Error: " << WSAGetLastError() << std::endl;
    } else {
        std::cout << "[Client] Sent client info to server: " << msg.clientInfo.username << "@" << msg.clientInfo.hostname << std::endl;
    }
}

std::string ExecuteCommand(const char* cmd) {
    std::string result = "";
    char buffer[256]; // Маленький буфер для _popen вывода
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) {
        return "[Client] ERROR: _popen() failed!";
    }
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        _pclose(pipe);
        return "[Client] ERROR: Exception while reading pipe for ExecuteCommand!";
    }
    int close_result = _pclose(pipe);
    if (close_result == -1) {
        // result += "\n[Client] ERROR: _pclose() failed after ExecuteCommand!";
        // Не всегда ошибка, может быть, если процесс завершился нештатно
    }
    if (result.empty()) {
        return "[Client] (Command produced no output or completed silently)";
    }
    return result;
}

void SendOutputToServer(SOCKET sock, const std::string& output) {
    if (output.empty()) {
        return;
    }
    Message msg;
    ZeroMemory(&msg, sizeof(Message)); 
    msg.type = MessageType::INTERACTIVE_OUTPUT;
    strncpy_s(msg.data, output.c_str(), BUFFER_SIZE - 1);
    msg.data[BUFFER_SIZE - 1] = '\0';

    if (send(sock, (char*)&msg, sizeof(Message), 0) == SOCKET_ERROR) {
        std::cerr << "[Client] Failed to send interactive output to server. Error: " << WSAGetLastError() << std::endl;
    }
}

void ReadFromPipeAndSend(SOCKET sock) {
    char read_buffer[BUFFER_SIZE]; 
    DWORD dwRead;
    BOOL bSuccess = FALSE;
    HANDLE hPipeToRead = g_hChildStd_OUT_Rd; 

    if (hPipeToRead == NULL || hPipeToRead == INVALID_HANDLE_VALUE) {
        std::cerr << "[Client-ReadPipe] Error: Pipe handle for reading shell output is NULL or Invalid." << std::endl;
        return;
    }
    std::cout << "[Client-ReadPipe] Thread started to read shell output." << std::endl;

    while (g_isShellActive.load()) { 
        DWORD dwAvail = 0;
        if (!PeekNamedPipe(hPipeToRead, NULL, 0, NULL, &dwAvail, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                std::cout << "[Client-ReadPipe] Pipe broken (PeekNamedPipe). Shell process likely terminated." << std::endl;
                break; 
            }
        }
        if (dwAvail > 0) { 
            bSuccess = ReadFile(hPipeToRead, read_buffer, BUFFER_SIZE - 1, &dwRead, NULL);
            if (!bSuccess || dwRead == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    std::cout << "[Client-ReadPipe] Pipe broken (ReadFile). Shell process likely terminated." << std::endl;
                } else if (!bSuccess) {
                    std::cerr << "[Client-ReadPipe] ReadFile from pipe failed. Error: " << GetLastError() << std::endl;
                }
                break; 
            }
            read_buffer[dwRead] = '\0'; 
            SendOutputToServer(sock, std::string(read_buffer));
        } else {
            if (!g_isShellActive.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); 
        }
    }
    std::cout << "[Client-ReadPipe] Thread finished reading shell output." << std::endl;
}

bool CreateShellProcess(const std::string& shellPath) {
    // Мьютекс УПРАВЛЯЕТСЯ ИЗВНЕ (в StartInteractiveShell/StopInteractiveShell)
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE; 
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
        std::cerr << "[Client-CreateShell] Stdout CreatePipe failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "[Client-CreateShell] Stdout Rd SetHandleInformation failed. Error: " << GetLastError() << std::endl;
        CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);
        g_hChildStd_OUT_Rd = NULL; g_hChildStd_OUT_Wr = NULL;
        return false;
    }
    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
        std::cerr << "[Client-CreateShell] Stdin CreatePipe failed. Error: " << GetLastError() << std::endl;
        CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr); 
        g_hChildStd_OUT_Rd = NULL; g_hChildStd_OUT_Wr = NULL;
        return false;
    }
    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "[Client-CreateShell] Stdin Wr SetHandleInformation failed. Error: " << GetLastError() << std::endl;
        CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);
        CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
        g_hChildStd_OUT_Rd = NULL; g_hChildStd_OUT_Wr = NULL; g_hChildStd_IN_Rd = NULL; g_hChildStd_IN_Wr = NULL;
        return false;
    }

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;  
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr; 
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;   
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES; 

    char commandLine[MAX_PATH]; 
    strncpy_s(commandLine, shellPath.c_str(), MAX_PATH - 1);
    commandLine[MAX_PATH - 1] = '\0';

    BOOL bSuccess = CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siStartInfo, &piProcInfo);

    if (!bSuccess) {
        std::cerr << "[Client-CreateShell] CreateProcess failed for '" << shellPath << "'. Error: " << GetLastError() << std::endl;
        CloseHandle(g_hChildStd_OUT_Rd); g_hChildStd_OUT_Rd = NULL;
        CloseHandle(g_hChildStd_OUT_Wr); g_hChildStd_OUT_Wr = NULL;
        CloseHandle(g_hChildStd_IN_Rd);  g_hChildStd_IN_Rd  = NULL;
        CloseHandle(g_hChildStd_IN_Wr);  g_hChildStd_IN_Wr  = NULL;
        return false;
    }

    g_hChildProcess = piProcInfo.hProcess;
    CloseHandle(piProcInfo.hThread);
    CloseHandle(g_hChildStd_OUT_Wr); g_hChildStd_OUT_Wr = NULL; 
    CloseHandle(g_hChildStd_IN_Rd);  g_hChildStd_IN_Rd  = NULL; 
    
    std::cout << "[Client-CreateShell] Successfully created shell process ('" << shellPath << "'). PID: " << piProcInfo.dwProcessId << std::endl;
    return true;
}

void StartInteractiveShell(SOCKET sock, const std::string& shellType) {
    std::unique_lock<std::mutex> lock(g_shellMutex);

    if (g_isShellActive.load()) {
        std::cerr << "[Client-StartShell] Shell type '" << g_currentShellType << "' is already active. Cannot start '" << shellType << "'." << std::endl;
        Message nackMsg; ZeroMemory(&nackMsg, sizeof(Message));
        nackMsg.type = MessageType::SHELL_START_FAILED;
        strncpy_s(nackMsg.data, "Shell already active on client.", BUFFER_SIZE - 1);
        send(sock, (char*)&nackMsg, sizeof(Message), 0); // Ошибку send здесь не обрабатываем критично
        return;
    }

    std::string shellPath;
    if (shellType == "cmd") {
        shellPath = "cmd.exe";
    } else if (shellType == "powershell") {
        shellPath = "powershell.exe"; 
    } else {
        std::cerr << "[Client-StartShell] Unsupported shell type: " << shellType << std::endl;
        Message nackMsg; ZeroMemory(&nackMsg, sizeof(Message));
        nackMsg.type = MessageType::SHELL_START_FAILED;
        std::string errMsg = "Unsupported shell type by client: " + shellType;
        strncpy_s(nackMsg.data, errMsg.c_str(), BUFFER_SIZE - 1);
        send(sock, (char*)&nackMsg, sizeof(Message), 0);
        return;
    }

    if (!CreateShellProcess(shellPath)) { 
        std::cerr << "[Client-StartShell] CreateShellProcess failed for " << shellType << std::endl;
        Message nackMsg; ZeroMemory(&nackMsg, sizeof(Message));
        nackMsg.type = MessageType::SHELL_START_FAILED;
        std::string errMsg = "Failed to create " + shellType + " process on client (internal error).";
        strncpy_s(nackMsg.data, errMsg.c_str(), BUFFER_SIZE - 1);
        send(sock, (char*)&nackMsg, sizeof(Message), 0);
        return;
    }

    g_currentShellType = shellType;
    g_isShellActive.store(true);
    std::cout << "[Client-StartShell] Shell '" << shellType << "' active. Starting reader thread." << std::endl;

    std::thread readerThread(ReadFromPipeAndSend, sock);
    readerThread.detach(); 

    Message ackMsg; ZeroMemory(&ackMsg, sizeof(Message));
    ackMsg.type = MessageType::SHELL_STARTED_ACK;
    strncpy_s(ackMsg.data, "OK", BUFFER_SIZE - 1);
    if (send(sock, (char*)&ackMsg, sizeof(Message), 0) == SOCKET_ERROR) {
        std::cerr << "[Client-StartShell] Failed to send SHELL_STARTED_ACK. Error: " << WSAGetLastError() << std::endl;
    }
    std::cout << "[Client-StartShell] Sent SHELL_STARTED_ACK for " << shellType << std::endl;
}

void StopInteractiveShell(SOCKET sock) {
    std::unique_lock<std::mutex> lock(g_shellMutex);
    if (!g_isShellActive.load()) {
        std::cout << "[Client-StopShell] No active shell to stop." << std::endl;
        return;
    }
    std::cout << "[Client-StopShell] Stopping interactive shell: " << g_currentShellType << std::endl;
    g_isShellActive.store(false); 

    if (g_hChildStd_IN_Wr != NULL && g_hChildStd_IN_Wr != INVALID_HANDLE_VALUE) {
        std::string exitCmd = "exit\n"; 
        DWORD dwWritten;
        WriteFile(g_hChildStd_IN_Wr, exitCmd.c_str(), (DWORD)exitCmd.length(), &dwWritten, NULL); // Ошибку здесь не обрабатываем критично
        CloseHandle(g_hChildStd_IN_Wr);
        g_hChildStd_IN_Wr = NULL;
    }

    if (g_hChildProcess != NULL && g_hChildProcess != INVALID_HANDLE_VALUE) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(g_hChildProcess, &exitCode) && exitCode == STILL_ACTIVE) {
            std::cout << "[Client-StopShell] Shell process still active. Terminating..." << std::endl;
            TerminateProcess(g_hChildProcess, 1);
        }
        CloseHandle(g_hChildProcess);
        g_hChildProcess = NULL;
    }

    if (g_hChildStd_OUT_Rd != NULL && g_hChildStd_OUT_Rd != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hChildStd_OUT_Rd);
        g_hChildStd_OUT_Rd = NULL;
    }
    // g_hChildStd_OUT_Wr и g_hChildStd_IN_Rd уже должны быть NULL после CreateShellProcess

    g_currentShellType = "";
    std::cout << "[Client-StopShell] Shell cleanup complete." << std::endl;

    Message ackMsg; ZeroMemory(&ackMsg, sizeof(Message));
    ackMsg.type = MessageType::SHELL_STOPPED_ACK;
    strncpy_s(ackMsg.data, "OK", BUFFER_SIZE - 1);
    if (send(sock, (char*)&ackMsg, sizeof(Message), 0) == SOCKET_ERROR) {
        std::cerr << "[Client-StopShell] Failed to send SHELL_STOPPED_ACK. Error: " << WSAGetLastError() << std::endl;
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Client] Winsock initialization failed. Error: " << WSAGetLastError() << std::endl; return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[Client] Socket creation failed. Error: " << WSAGetLastError() << std::endl; WSACleanup(); return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEFAULT_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) <= 0) {
        std::cerr << "[Client] Invalid address/ Address not supported. Error: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket); WSACleanup(); return 1;
    }

    if (connect(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[Client] Connection to server failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket); WSACleanup(); return 1;
    }
    std::cout << "[Client] Connected to server at 127.0.0.1:" << DEFAULT_PORT << std::endl;

    SendClientInfo(serverSocket);

    Message msg;
    while (true) {
        ZeroMemory(&msg, sizeof(Message));
        int bytesReceived = recv(serverSocket, (char*)&msg, sizeof(Message), 0);

        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "[Client] recv failed with error: " << WSAGetLastError() << std::endl;
            if (g_isShellActive.load()) { 
                std::cout << "[Client] Server connection lost. Stopping active shell..." << std::endl;
                StopInteractiveShell(serverSocket); 
            }
            break;
        }
        if (bytesReceived == 0) {
            std::cout << "[Client] Server closed connection." << std::endl;
            if (g_isShellActive.load()) { 
                std::cout << "[Client] Server closed connection. Stopping active shell..." << std::endl;
                StopInteractiveShell(serverSocket); 
            }
            break;
        }

        switch (msg.type) {
            case MessageType::COMMAND: {
                std::cout << "[Client] Received one-shot command: " << msg.data << std::endl;
                if (g_isShellActive.load()) {
                    std::cout << "[Client] Warning: Shell is active. One-shot command ignored." << std::endl;
                    Message replyMsg; ZeroMemory(&replyMsg, sizeof(Message));
                    replyMsg.type = MessageType::COMMAND_OUTPUT;
                    strncpy_s(replyMsg.data, "[Client] NACK: Interactive shell is active. Command ignored.", BUFFER_SIZE - 1);
                    send(serverSocket, (char*)&replyMsg, sizeof(Message),0);
                } else {
                    std::string output = ExecuteCommand(msg.data);
                    Message replyMsg; ZeroMemory(&replyMsg, sizeof(Message));
                    replyMsg.type = MessageType::COMMAND_OUTPUT;
                    strncpy_s(replyMsg.data, output.c_str(), BUFFER_SIZE - 1);
                    send(serverSocket, (char*)&replyMsg, sizeof(Message), 0);
                }
                break;
            }
            case MessageType::START_INTERACTIVE_SHELL: {
                std::cout << "[Client] Received START_INTERACTIVE_SHELL for type: " << msg.data << std::endl;
                StartInteractiveShell(serverSocket, std::string(msg.data));
                break;
            }
            case MessageType::STOP_INTERACTIVE_SHELL: {
                std::cout << "[Client] Received STOP_INTERACTIVE_SHELL request." << std::endl;
                StopInteractiveShell(serverSocket);
                break;
            }
            case MessageType::INTERACTIVE_INPUT: {
                if (g_isShellActive.load()) {
                    std::lock_guard<std::mutex> lock(g_shellMutex); 
                    if (g_hChildStd_IN_Wr != NULL && g_hChildStd_IN_Wr != INVALID_HANDLE_VALUE) {
                        DWORD dwWritten;
                        if (!WriteFile(g_hChildStd_IN_Wr, msg.data, (DWORD)strlen(msg.data), &dwWritten, NULL)) {
                            std::cerr << "[Client] WriteFile to shell STDIN failed. Error: " << GetLastError() << std::endl;
                        }
                    } else {
                        std::cerr << "[Client] Shell active, but STDIN write handle is NULL." << std::endl;
                    }
                } else {
                    std::cout << "[Client] Received INTERACTIVE_INPUT, but no shell is active. Ignored." << std::endl;
                }
                break;
            }
            case MessageType::REGULAR: {
                std::cout << "[Client] Received message from server: " << msg.data << std::endl;
                break;
            }
            case MessageType::TERMINATE_CLIENT: {
                std::cout << "[Client] Received TERMINATE_CLIENT command from server. Shutting down." << std::endl;
                closesocket(serverSocket);
                WSACleanup();
                std::cout << "[Client] Disconnected and cleaned up." << std::endl;
                return 0;
            }
            default:
                std::cout << "[Client] Received unhandled message type (" << static_cast<int>(msg.type) << ") from server: " << msg.data << std::endl;
                break;
        }
    }

    closesocket(serverSocket);
    WSACleanup();
    std::cout << "[Client] Disconnected and cleaned up." << std::endl;
    return 0;
} 