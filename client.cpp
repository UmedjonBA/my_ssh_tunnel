#define WIN32_LEAN_AND_MEAN // Исключаем редко используемые компоненты из заголовков Windows

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string> // Для std::string
#include <vector> // Для std::vector если понадобится
#include <atomic> // For std::atomic_bool

// Не забываем подключить библиотеку Ws2_32.lib при компиляции
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#include "common.h" // Подключаем наш общий заголовочный файл

// Global flag to signal termination of relay threads
std::atomic<bool> g_interactiveSessionShouldTerminate(false);

struct RelayParams {
    SOCKET socket;
    HANDLE hChildProcess_StdOut_Rd;
    HANDLE hChildProcess_StdIn_Wr;
    // We might add a handle for stderr_Rd if we decide to read it separately
};

// Функция для выполнения команды и отправки ее вывода на сокет
// Возвращает true при успехе (даже если команда завершилась с ошибкой, но процесс запустился и вывод обработан)
// Возвращает false при критической ошибке (не удалось создать процесс, пайп или ошибка сокета)
bool ExecuteCommandAndSendOutput(const std::string& command, SOCKET sock) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;

    // Создаем пайп для stdout дочернего процесса
    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &sa, 0)) {
        std::cerr << "Client Error: StdoutRd CreatePipe failed: " << GetLastError() << std::endl;
        return false;
    }
    // Убеждаемся, что read-хендл пайпа для stdout не наследуется
    if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Client Error: Stdout SetHandleInformation failed: " << GetLastError() << std::endl;
        CloseHandle(hChildStd_OUT_Rd); CloseHandle(hChildStd_OUT_Wr);
        return false;
    }

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;
    BOOL bProcessSuccess = FALSE;

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = hChildStd_OUT_Wr; // Перенаправляем stderr в тот же пайп, что и stdout
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    // siStartInfo.hStdInput = NULL; // Пока не передаем stdin
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // CreateProcessA может модифицировать строку команды, поэтому передаем копию
    char szCmdline[DEFAULT_BUFLEN]; 
    strncpy_s(szCmdline, sizeof(szCmdline), command.c_str(), _TRUNCATE);

    std::cout << "Client: Attempting to execute command: '" << szCmdline << "'" << std::endl;

    bProcessSuccess = CreateProcessA(
        NULL,           // Имя модуля не используется
        szCmdline,      // Строка команды
        NULL,           // Дескриптор процесса не наследуется
        NULL,           // Дескриптор потока не наследуется
        TRUE,           // Наследование дескрипторов установлено в TRUE
        CREATE_NO_WINDOW, // Не создаем консольное окно для дочернего процесса
        NULL,           // Используем окружение родителя
        NULL,           // Используем текущую директорию родителя
        &siStartInfo,   // Указатель на структуру STARTUPINFOA
        &piProcInfo);   // Указатель на структуру PROCESS_INFORMATION

    if (!bProcessSuccess) {
        std::cerr << "Client Error: CreateProcess failed: " << GetLastError() << " for command: " << command << std::endl;
        CloseHandle(hChildStd_OUT_Rd); CloseHandle(hChildStd_OUT_Wr);
        // Отправим сообщение об ошибке серверу
        std::string errorMsg = "Failed to execute command on client: CreateProcess error " + std::to_string(GetLastError());
        send(sock, errorMsg.c_str(), errorMsg.length() + 1, 0);
        const char* eof_marker_on_error = "\n--CMD_EOF--\n";
        send(sock, eof_marker_on_error, strlen(eof_marker_on_error), 0);
        return false; // Ошибка создания процесса
    }
    std::cout << "Client: Process " << piProcInfo.dwProcessId << " created." << std::endl;

    // Закрываем write-конец пайпа в родительском процессе.
    // Это важно, чтобы ReadFile на read-конце в итоге вернул 0 (EOF).
    if (!CloseHandle(hChildStd_OUT_Wr)) {
        std::cerr << "Client Warning: StdOutWr CloseHandle failed: " << GetLastError() << std::endl;
        // Не критично для продолжения, но может повлиять на чтение
    }
    hChildStd_OUT_Wr = NULL; // Помечаем как закрытый

    // Читаем вывод из пайпа дочернего процесса и отправляем на сервер
    CHAR chBuf[DEFAULT_BUFLEN]; // Используем DEFAULT_BUFLEN, как и для сокета
    DWORD dwRead;
    bool socket_send_error = false;

    for (;;) {
        // std::cout << "Client: Attempting to ReadFile from pipe..." << std::endl; // Debug
        BOOL bReadSuccess = ReadFile(hChildStd_OUT_Rd, chBuf, DEFAULT_BUFLEN -1 , &dwRead, NULL);
        // std::cout << "Client: ReadFile returned " << bReadSuccess << ", dwRead = " << dwRead << std::endl; // Debug

        if (!bReadSuccess || dwRead == 0) {
            if (!bReadSuccess) {
                 int error = GetLastError();
                 if (error != ERROR_BROKEN_PIPE) { // ERROR_BROKEN_PIPE ожидаем при закрытии пайпа процессом
                    std::cerr << "Client Warning: ReadFile from pipe failed: " << error << std::endl;
                 }
            }
            //std::cout << "Client: Pipe read EOF or error." << std::endl; // Debug
            break; // EOF или ошибка чтения из пайпа
        }
        
        // Отправляем прочитанный блок на сервер (dwRead байт, не null-терминируем здесь, т.к. могут быть бинарные данные)
        int sendResult = send(sock, chBuf, dwRead, 0);
        if (sendResult == SOCKET_ERROR) {
            std::cerr << "Client Error: Send output chunk failed: " << WSAGetLastError() << std::endl;
            socket_send_error = true; 
            break;
        }
        //std::cout << "Client: Sent " << dwRead << " bytes to server." << std::endl; // Debug
    }
    
    // Отправляем маркер конца вывода
    const char* eof_marker = "\n--CMD_EOF--\n";
    if (send(sock, eof_marker, strlen(eof_marker), 0) == SOCKET_ERROR) {
         std::cerr << "Client Error: Send EOF marker failed: " << WSAGetLastError() << std::endl;
         socket_send_error = true; // Считаем это ошибкой для возвращаемого значения
    }
    //std::cout << "Client: Sent EOF marker." << std::endl; // Debug

    // Ожидаем завершения дочернего процесса
    //std::cout << "Client: Waiting for process " << piProcInfo.dwProcessId << " to finish..." << std::endl; // Debug
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);
    //std::cout << "Client: Process " << piProcInfo.dwProcessId << " finished." << std::endl; // Debug

    DWORD exitCode = 0;
    GetExitCodeProcess(piProcInfo.hProcess, &exitCode);
    std::cout << "Client: Process " << piProcInfo.dwProcessId << " exited with code " << exitCode << "." << std::endl;

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
    CloseHandle(hChildStd_OUT_Rd); 

    return !socket_send_error;
}

// Thread function to read from process output and send to socket
DWORD WINAPI ReadFromProcessAndSend(LPVOID lpParam) {
    RelayParams* params = (RelayParams*)lpParam;
    char buffer[DEFAULT_BUFLEN];
    DWORD bytesRead;

    // std::cout << "[Client-RelayOut]: ReadFromProcessAndSend thread (ID: " << GetCurrentThreadId() << ") started." << std::endl;

    while (!g_interactiveSessionShouldTerminate.load()) {
        // ReadFile will block until data is available, EOF is reached, or an error occurs.
        if (!ReadFile(params->hChildProcess_StdOut_Rd, buffer, sizeof(buffer) -1 , &bytesRead, NULL) || bytesRead == 0) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                // std::cout << "[Client-RelayOut]: Pipe broken (child process likely exited or closed its stdout)." << std::endl;
            } else {
                // std::cout << "[Client-RelayOut]: ReadFile from pipe failed or read 0 bytes. Error: " << GetLastError() << std::endl;
            }
            g_interactiveSessionShouldTerminate.store(true); // Signal other thread to terminate
            break;
        }
        // buffer[bytesRead] = '\0'; // Do not null-terminate if sending raw binary data
        // std::cout << "[Client-RelayOut]: Read " << bytesRead << " bytes. Sending to server." << std::endl;

        int sendResult = send(params->socket, buffer, bytesRead, 0);
        if (sendResult == SOCKET_ERROR) {
            // std::cerr << "[Client-RelayOut]: Send to socket failed: " << WSAGetLastError() << std::endl;
            g_interactiveSessionShouldTerminate.store(true); // Signal other thread to terminate
            break;
        }
    }
    // std::cout << "[Client-RelayOut]: ReadFromProcessAndSend thread (ID: " << GetCurrentThreadId() << ") finished." << std::endl;
    return 0;
}

// Thread function to read from socket and write to process input
DWORD WINAPI ReadFromSocketAndWrite(LPVOID lpParam) {
    RelayParams* params = (RelayParams*)lpParam;
    char buffer[DEFAULT_BUFLEN];
    DWORD bytesWritten;

    // std::cout << "[Client-RelayIn]: ReadFromSocketAndWrite thread (ID: " << GetCurrentThreadId() << ") started." << std::endl;

    while (!g_interactiveSessionShouldTerminate.load()) {
        int bytesReceived = recv(params->socket, buffer, sizeof(buffer), 0);
        if (bytesReceived > 0) {
            // std::cout << "[Client-RelayIn]: Received " << bytesReceived << " bytes from socket. Writing to child stdin." << std::endl;
            if (!WriteFile(params->hChildProcess_StdIn_Wr, buffer, bytesReceived, &bytesWritten, NULL) || bytesWritten != (DWORD)bytesReceived) {
                // std::cerr << "[Client-RelayIn]: WriteFile to pipe failed: " << GetLastError() << std::endl;
                g_interactiveSessionShouldTerminate.store(true); // Signal other thread to terminate
                break;
            }
        } else if (bytesReceived == 0) {
            // std::cout << "[Client-RelayIn]: Socket closed by server (recv returned 0). Signaling termination." << std::endl;
            g_interactiveSessionShouldTerminate.store(true); 
            break;
        } else { // SOCKET_ERROR
            int error = WSAGetLastError();
            // std::cerr << "[Client-RelayIn]: Recv from socket failed: " << error << ". Signaling termination." << std::endl;
            if (error != WSAECONNABORTED && error != WSAECONNRESET) {
                 // Only signal termination for critical errors, not just if the socket was closed by server while we were waiting for process to end
            }
            g_interactiveSessionShouldTerminate.store(true); 
            break;
        }
    }
    // std::cout << "[Client-RelayIn]: ReadFromSocketAndWrite thread (ID: " << GetCurrentThreadId() << ") finished." << std::endl;
    // Close the write-end of the child's stdin pipe to signal EOF to the child process.
    // This is important for shell commands like `exit` or `logout` to work correctly.
    CloseHandle(params->hChildProcess_StdIn_Wr);
    params->hChildProcess_StdIn_Wr = NULL; // Mark as closed
    return 0;
}

bool StartInteractiveShellAndRelay(const std::string& shellCommand, SOCKET sock) {
    std::cout << "Client: Attempting to start interactive shell: '" << shellCommand << "'" << std::endl;
    g_interactiveSessionShouldTerminate.store(false); // Reset flag for the new session

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hChild_StdIn_Rd = NULL, hChild_StdIn_Wr = NULL;
    HANDLE hChild_StdOut_Rd = NULL, hChild_StdOut_Wr = NULL;
    // We'll redirect stderr to stdout for simplicity for now.

    // Create pipe for child process's STDOUT
    if (!CreatePipe(&hChild_StdOut_Rd, &hChild_StdOut_Wr, &sa, 0)) {
        std::cerr << "Client Error: StdOut CreatePipe failed: " << GetLastError() << std::endl; return false;
    }
    if (!SetHandleInformation(hChild_StdOut_Rd, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Client Error: StdOut SetHandleInformation failed: " << GetLastError() << std::endl;
        CloseHandle(hChild_StdOut_Rd); CloseHandle(hChild_StdOut_Wr); return false;
    }

    // Create pipe for child process's STDIN
    if (!CreatePipe(&hChild_StdIn_Rd, &hChild_StdIn_Wr, &sa, 0)) {
        std::cerr << "Client Error: StdIn CreatePipe failed: " << GetLastError() << std::endl;
        CloseHandle(hChild_StdOut_Rd); CloseHandle(hChild_StdOut_Wr); return false;
    }
    if (!SetHandleInformation(hChild_StdIn_Wr, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Client Error: StdIn SetHandleInformation failed: " << GetLastError() << std::endl;
        CloseHandle(hChild_StdOut_Rd); CloseHandle(hChild_StdOut_Wr);
        CloseHandle(hChild_StdIn_Rd); CloseHandle(hChild_StdIn_Wr); return false;
    }

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = hChild_StdOut_Wr; // Redirect stderr to the same pipe as stdout
    siStartInfo.hStdOutput = hChild_StdOut_Wr;
    siStartInfo.hStdInput = hChild_StdIn_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    char szCmdline[DEFAULT_BUFLEN];
    strncpy_s(szCmdline, sizeof(szCmdline), shellCommand.c_str(), _TRUNCATE);

    BOOL bProcessSuccess = CreateProcessA(NULL, szCmdline, NULL, NULL, TRUE, 
                                       CREATE_NO_WINDOW, // No console window for the child
                                       NULL, NULL, &siStartInfo, &piProcInfo);

    if (!bProcessSuccess) {
        std::cerr << "Client Error: CreateProcess for interactive shell ('" << shellCommand << "') failed: " << GetLastError() << std::endl;
        CloseHandle(hChild_StdOut_Rd); CloseHandle(hChild_StdOut_Wr);
        CloseHandle(hChild_StdIn_Rd); CloseHandle(hChild_StdIn_Wr);
        std::string errorMsg = "Failed to start interactive shell on client: CreateProcess error " + std::to_string(GetLastError());
        send(sock, errorMsg.c_str(), errorMsg.length() +1 , 0);
        const char* interactive_error_eof_marker = "\n--INTERACTIVE_ERROR_EOF--\n"; // Specific marker for this error
        send(sock, interactive_error_eof_marker, strlen(interactive_error_eof_marker), 0);
        return false;
    }

    // Close handles not needed by the parent process
    CloseHandle(hChild_StdOut_Wr); hChild_StdOut_Wr = NULL; // Parent does not write to child's stdout
    CloseHandle(hChild_StdIn_Rd);  hChild_StdIn_Rd = NULL;  // Parent does not read from child's stdin

    RelayParams params;
    params.socket = sock;
    params.hChildProcess_StdOut_Rd = hChild_StdOut_Rd; // Parent reads from this
    params.hChildProcess_StdIn_Wr = hChild_StdIn_Wr;   // Parent writes to this

    HANDLE hThreads[2];
    hThreads[0] = CreateThread(NULL, 0, ReadFromProcessAndSend, &params, 0, NULL);
    hThreads[1] = CreateThread(NULL, 0, ReadFromSocketAndWrite, &params, 0, NULL);

    if (hThreads[0] == NULL || hThreads[1] == NULL) {
        std::cerr << "Client Error: Failed to create one or more relay threads." << std::endl;
        g_interactiveSessionShouldTerminate.store(true); // Signal any created thread to terminate
        
        if (hThreads[0]) { WaitForSingleObject(hThreads[0], 1000); CloseHandle(hThreads[0]); }
        if (hThreads[1]) { WaitForSingleObject(hThreads[1], 1000); CloseHandle(hThreads[1]); }

        TerminateProcess(piProcInfo.hProcess, 1); // Kill the child process
        CloseHandle(piProcInfo.hProcess); CloseHandle(piProcInfo.hThread);
        CloseHandle(params.hChildProcess_StdOut_Rd); // This is hChild_StdOut_Rd
        if (params.hChildProcess_StdIn_Wr) CloseHandle(params.hChildProcess_StdIn_Wr); // This is hChild_StdIn_Wr, may be closed by thread
        // Send error marker to server
        const char* thread_error_eof_marker = "\n--INTERACTIVE_THREAD_ERROR_EOF--\n";
        send(sock, thread_error_eof_marker, strlen(thread_error_eof_marker), 0);
        return false;
    }

    std::cout << "Client: Interactive shell process " << piProcInfo.dwProcessId << " started. Relay threads running." << std::endl;

    // Wait for the child process to terminate.
    // When the child process terminates, its stdout/stderr pipes will be closed.
    // This will cause ReadFile in ReadFromProcessAndSend to return (0 or error), which sets g_interactiveSessionShouldTerminate.
    // This, in turn, will cause ReadFromSocketAndWrite to break its loop and terminate.
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);
    std::cout << "Client: Interactive shell process " << piProcInfo.dwProcessId << " has terminated." << std::endl;
    
    // Ensure the global termination flag is set, in case the process terminated before threads could react or if there was an issue.
    g_interactiveSessionShouldTerminate.store(true);

    // Wait for both relay threads to finish.
    // It's important they clean up (especially ReadFromSocketAndWrite closing its pipe handle).
    DWORD waitResult = WaitForMultipleObjects(2, hThreads, TRUE, 5000); // Wait up to 5 seconds for both threads
    if (waitResult == WAIT_TIMEOUT) {
        std::cout << "Client Warning: Relay threads did not terminate gracefully within timeout." << std::endl;
        // Consider TerminateThread as a last resort, but it's generally unsafe.
        // if(hThreads[0]) TerminateThread(hThreads[0], 1);
        // if(hThreads[1]) TerminateThread(hThreads[1], 1);
    }

    CloseHandle(hThreads[0]);
    CloseHandle(hThreads[1]);

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    // Clean up remaining pipe handles that belong to the parent process.
    // params.hChildProcess_StdOut_Rd is hChild_StdOut_Rd, used by ReadFromProcessAndSend
    // params.hChildProcess_StdIn_Wr is hChild_StdIn_Wr, used by ReadFromSocketAndWrite (it closes this one itself)
    CloseHandle(params.hChildProcess_StdOut_Rd); 
    // params.hChildProcess_StdIn_Wr is closed by its thread. If not, it would be a bug.
    // if (params.hChildProcess_StdIn_Wr) { CloseHandle(params.hChildProcess_StdIn_Wr); }
 
    std::cout << "Client: Interactive session cleanup complete." << std::endl;

    // Send a specific EOF marker to the server to indicate the end of the interactive session.
    const char* interactive_eof_marker = "\n--INTERACTIVE_EOF--\n";
    if (send(sock, interactive_eof_marker, strlen(interactive_eof_marker), 0) == SOCKET_ERROR) {
        std::cerr << "Client Warning: Failed to send INTERACTIVE_EOF marker: " << WSAGetLastError() << std::endl;
    }
    
    return true;
}

int main(int argc, char **argv) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
    // Используем localhost как адрес сервера по умолчанию
    const char* serverHostname = "localhost";
    int iResult;

    // Валидация аргументов командной строки (позже можно будет передавать адрес сервера)
    // if (argc != 2) {
    //     printf("usage: %s server-name\n", argv[0]);
    //     return 1;
    // }

    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
    std::cout << "Client: Winsock initialized." << std::endl;

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC; // AF_INET для IPv4, AF_INET6 для IPv6, AF_UNSPEC для любого
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Получение информации об адресе сервера
    iResult = getaddrinfo(serverHostname, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    std::cout << "Client: Address info for " << serverHostname << ":" << DEFAULT_PORT << " obtained." << std::endl;

    // Пытаемся подключиться к адресу, пока не получится
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {
        // Создание сокета для подключения к серверу
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Подключение к серверу
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            // printf("Client: Failed to connect to server. Retrying...\n"); // Убрал Retry для простоты
            continue;
        }
        break; // Если подключение успешно, выходим из цикла
    }

    freeaddrinfo(result); // Освобождаем структуру addrinfo

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Client: Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    std::cout << "Client: Connected to server!" << std::endl;

    // Аутентификация: отправка имени пользователя и имени машины
    char username[DEFAULT_BUFLEN];
    //DWORD username_len = DEFAULT_BUFLEN; // Старая переменная, переименована
    DWORD username_len_actual = DEFAULT_BUFLEN; // Будет заполнена реальной длиной
    if (!GetUserNameA(username, &username_len_actual)) { 
        printf("GetUserNameA failed with error: %ld. Required buffer size (if error was due to small buffer): %lu\n", GetLastError(), username_len_actual);
        closesocket(ConnectSocket); WSACleanup(); return 1;
    } else {
        // username_len_actual теперь содержит длину БЕЗ null-терминатора. Отправляем username_len_actual + 1 байт.
        iResult = send(ConnectSocket, username, username_len_actual + 1, 0); 
        if (iResult == SOCKET_ERROR) {
            printf("send failed for username with error: %d\n", WSAGetLastError());
            closesocket(ConnectSocket); WSACleanup(); return 1;
        }
        std::cout << "Client: Sent username: " << username << std::endl;
    }

    char computerName[DEFAULT_BUFLEN];
    //DWORD computerName_len_buffer = DEFAULT_BUFLEN; // Старая переменная
    DWORD computerName_len_actual = DEFAULT_BUFLEN; // Будет заполнена реальной длиной
    if (!GetComputerNameA(computerName, &computerName_len_actual)) { 
        printf("GetComputerNameA failed with error: %ld. Required buffer size (if error was due to small buffer): %lu\n", GetLastError(), computerName_len_actual);
        closesocket(ConnectSocket); WSACleanup(); return 1;
    } else {
        // computerName_len_actual теперь содержит длину БЕЗ null-терминатора. Отправляем +1 байт.
        iResult = send(ConnectSocket, computerName, computerName_len_actual + 1, 0);
        if (iResult == SOCKET_ERROR) {
            printf("send failed for computer name with error: %d\n", WSAGetLastError());
            closesocket(ConnectSocket); WSACleanup(); return 1;
        }
        std::cout << "Client: Sent computer name: " << computerName << ". Waiting for commands..." << std::endl;
    }

    // Цикл приема команд от сервера и их выполнения
    char recvbuf_cmd[DEFAULT_BUFLEN];
    int recvbuflen_cmd = DEFAULT_BUFLEN;

    while (true) {
        iResult = recv(ConnectSocket, recvbuf_cmd, recvbuflen_cmd - 1, 0);
        if (iResult > 0) {
            recvbuf_cmd[iResult] = '\0'; 
            std::string command_received = recvbuf_cmd;
            std::cout << "Client: Received command from server: '" << command_received << "'" << std::endl;
            
            if (command_received.rfind("START_INTERACTIVE_SHELL:", 0) == 0) {
                std::string shell_to_run = command_received.substr(strlen("START_INTERACTIVE_SHELL:"));
                if (!shell_to_run.empty()) {
                    if (!StartInteractiveShellAndRelay(shell_to_run, ConnectSocket)) {
                        std::cerr << "Client: Interactive shell session for '" << shell_to_run << "' failed or was aborted." << std::endl;
                        // The function StartInteractiveShellAndRelay should send its own error markers.
                        // The connection might be in an unstable state. Depending on protocol, might break or continue.
                    }
                    // After StartInteractiveShellAndRelay returns, the interactive session is over.
                    // Client returns to its normal command loop, waiting for next command.
                    std::cout << "Client: Returned from interactive shell mode. Awaiting next command." << std::endl;
                } else {
                    std::cerr << "Client Error: Received empty shell name for START_INTERACTIVE_SHELL." << std::endl;
                    // Send an error back to the server using the non-interactive command EOF style
                    std::string errorMsg = "Client Error: Empty shell name for START_INTERACTIVE_SHELL.";
                    send(ConnectSocket, errorMsg.c_str(), errorMsg.length() + 1, 0);
                    const char* eof_marker_on_error = "\n--CMD_EOF--\n"; // Use standard non-interactive EOF
                    send(ConnectSocket, eof_marker_on_error, strlen(eof_marker_on_error), 0);
                }
            } else if (command_received == "exit_client_session") { // Специальная команда для корректного завершения
                 std::cout << "Client: Received exit_client_session command. Shutting down." << std::endl;
                 break;
            }
            // Make sure this is an 'else if' or just 'else' for non-interactive commands.
            // If it's not an interactive shell command, and not exit, then it's a non-interactive command.
            else { 
                // std::cout << "Client: Executing non-interactive command: '" << command_received << "'" << std::endl;
                if (!ExecuteCommandAndSendOutput(command_received, ConnectSocket)) {
                    std::cerr << "Client: Critical error during non-interactive command execution or sending output for: " << command_received << std::endl;
                }
            }
        } else if (iResult == 0) {
            std::cout << "Client: Server closed connection while waiting for command." << std::endl;
            break; 
        } else {
            printf("Client: recv (waiting for command) failed with error: %d\n", WSAGetLastError());
            break; 
        }
    }

    std::cout << "Client: Shutting down socket." << std::endl;
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        // WSAENOTCONN - это нормально, если сервер уже закрыл соединение
        if (WSAGetLastError() != WSAENOTCONN) {
             printf("shutdown failed with error: %d\n", WSAGetLastError());
        }
    }
    closesocket(ConnectSocket);
    WSACleanup();
    std::cout << "Client: Cleanup complete. Exiting." << std::endl;
    return 0;
} 