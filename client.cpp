#include "common.h"
#include <iostream>
#include <thread>
#include <string>
#include <Lmcons.h>
#include <windows.h>

// Глобальные переменные для интерактивного режима
HANDLE g_hCmdProcess = NULL;
HANDLE g_hCmdStdin = NULL;
HANDLE g_hCmdStdout = NULL;
HANDLE g_hCmdStderr = NULL;
bool g_isInteractiveMode = false;

void CleanupCmdProcess() {
    if (g_hCmdStdin) CloseHandle(g_hCmdStdin);
    if (g_hCmdStdout) CloseHandle(g_hCmdStdout);
    if (g_hCmdStderr) CloseHandle(g_hCmdStderr);
    if (g_hCmdProcess) CloseHandle(g_hCmdProcess);
    g_hCmdStdin = NULL;
    g_hCmdStdout = NULL;
    g_hCmdStderr = NULL;
    g_hCmdProcess = NULL;
    g_isInteractiveMode = false;
}

bool StartInteractiveCmd() {
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Создаем pipes для stdin, stdout и stderr
    HANDLE hStdinRead, hStdinWrite;
    HANDLE hStdoutRead, hStdoutWrite;
    HANDLE hStderrRead, hStderrWrite;

    if (!CreatePipe(&hStdinRead, &hStdinWrite, &saAttr, 0) ||
        !CreatePipe(&hStdoutRead, &hStdoutWrite, &saAttr, 0) ||
        !CreatePipe(&hStderrRead, &hStderrWrite, &saAttr, 0)) {
        return false;
    }

    // Убеждаемся, что дочерний процесс не унаследует концы для чтения
    if (!SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0)) {
        CleanupCmdProcess();
        return false;
    }

    // Настраиваем структуру STARTUPINFO
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;

    // Настраиваем структуру PROCESS_INFORMATION
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Создаем процесс cmd.exe
    if (!CreateProcessA(
        NULL,
        (LPSTR)"cmd.exe",
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi)) {
        CleanupCmdProcess();
        return false;
    }

    // Сохраняем дескрипторы
    g_hCmdProcess = pi.hProcess;
    g_hCmdStdin = hStdinWrite;
    g_hCmdStdout = hStdoutRead;
    g_hCmdStderr = hStderrRead;
    g_isInteractiveMode = true;

    // Закрываем ненужные дескрипторы
    CloseHandle(pi.hThread);
    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);

    return true;
}

std::string ExecuteCommand(const std::string& command) {
    if (!g_isInteractiveMode) {
        // Если не в интерактивном режиме, запускаем новый процесс
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        HANDLE hReadPipe, hWritePipe;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
            return "Failed to create pipe";
        }

        if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return "Failed to set pipe attributes";
        }

        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.hStdInput = NULL;

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        std::string cmdLine = "cmd.exe /c " + command;
        char* cmdLineStr = new char[cmdLine.length() + 1];
        strcpy_s(cmdLineStr, cmdLine.length() + 1, cmdLine.c_str());

        BOOL success = CreateProcessA(
            NULL,
            cmdLineStr,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        delete[] cmdLineStr;

        if (!success) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return "Failed to create process";
        }

        CloseHandle(hWritePipe);

        std::string result;
        char buffer[BUFFER_SIZE];
        DWORD bytesRead;
        
        while (true) {
            if (!ReadFile(hReadPipe, buffer, BUFFER_SIZE - 1, &bytesRead, NULL) || bytesRead == 0) {
                break;
            }
            buffer[bytesRead] = '\0';
            result += buffer;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);

        if (exitCode != 0) {
            result += "\nProcess exited with code: " + std::to_string(exitCode);
        }

        return result;
    } else {
        // В интерактивном режиме отправляем команду в существующий процесс
        DWORD bytesWritten;
        std::string cmdWithNewline = command + "\n";
        if (!WriteFile(g_hCmdStdin, cmdWithNewline.c_str(), cmdWithNewline.length(), &bytesWritten, NULL)) {
            return "Failed to write to cmd process";
        }

        // Читаем вывод
        std::string result;
        char buffer[BUFFER_SIZE];
        DWORD bytesRead;
        
        // Даем небольшую задержку для начала выполнения команды
        Sleep(50);
        
        // Читаем вывод несколько раз с небольшими интервалами
        for (int i = 0; i < 5; i++) {
            while (true) {
                if (!ReadFile(g_hCmdStdout, buffer, BUFFER_SIZE - 1, &bytesRead, NULL) || bytesRead == 0) {
                    break;
                }
                buffer[bytesRead] = '\0';
                result += buffer;
            }
            Sleep(50); // Небольшая пауза между попытками чтения
        }

        // Проверяем stderr на наличие ошибок
        while (true) {
            if (!ReadFile(g_hCmdStderr, buffer, BUFFER_SIZE - 1, &bytesRead, NULL) || bytesRead == 0) {
                break;
            }
            buffer[bytesRead] = '\0';
            result += buffer;
        }

        return result;
    }
}

void HandleServerCommands(SOCKET sock) {
    Message msg;
    while (true) {
        int bytesReceived = recv(sock, (char*)&msg, sizeof(Message), 0);
        if (bytesReceived <= 0) {
            std::cout << "Disconnected from server" << std::endl;
            break;
        }

        if (msg.type == MessageType::COMMAND) {
            std::cout << "\n[" << GetTickCount64() << "] Received command: " << msg.data << std::endl;
            std::cout << "----------------------------------------" << std::endl;
            
            ULONGLONG startTime = GetTickCount64();
            
            // Если команда "interactive", переключаемся в интерактивный режим
            if (strcmp(msg.data, "interactive") == 0) {
                if (StartInteractiveCmd()) {
                    std::string output = "Switched to interactive mode";
                    std::cout << output << std::endl;
                    
                    Message response;
                    response.type = MessageType::COMMAND_OUTPUT;
                    strncpy_s(response.data, output.c_str(), BUFFER_SIZE - 1);
                    send(sock, (char*)&response, sizeof(Message), 0);
                } else {
                    std::string output = "Failed to start interactive mode";
                    std::cout << output << std::endl;
                    
                    Message response;
                    response.type = MessageType::COMMAND_OUTPUT;
                    strncpy_s(response.data, output.c_str(), BUFFER_SIZE - 1);
                    send(sock, (char*)&response, sizeof(Message), 0);
                }
            }
            // Если команда "exit_interactive", выходим из интерактивного режима
            else if (strcmp(msg.data, "exit_interactive") == 0) {
                CleanupCmdProcess();
                std::string output = "Exited interactive mode";
                std::cout << output << std::endl;
                
                Message response;
                response.type = MessageType::COMMAND_OUTPUT;
                strncpy_s(response.data, output.c_str(), BUFFER_SIZE - 1);
                send(sock, (char*)&response, sizeof(Message), 0);
            }
            else {
                std::string output = ExecuteCommand(msg.data);
                
                ULONGLONG endTime = GetTickCount64();
                ULONGLONG executionTime = endTime - startTime;
                
                std::cout << output << std::endl;
                std::cout << "----------------------------------------" << std::endl;
                std::cout << "Execution time: " << executionTime << "ms" << std::endl;
                
                Message response;
                response.type = MessageType::COMMAND_OUTPUT;
                strncpy_s(response.data, output.c_str(), BUFFER_SIZE - 1);
                send(sock, (char*)&response, sizeof(Message), 0);
            }
        }
    }
    
    // При отключении от сервера очищаем процесс cmd
    CleanupCmdProcess();
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEFAULT_PORT);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Failed to connect to server" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // Получаем имя пользователя и имя компьютера
    char hostname[MAX_NAME_LENGTH];
    DWORD hostnameLen = sizeof(hostname);
    GetComputerNameA(hostname, &hostnameLen);

    char username[MAX_NAME_LENGTH];
    DWORD usernameLen = MAX_NAME_LENGTH;
    GetUserNameA(username, &usernameLen);

    // Отправляем информацию о клиенте
    Message initMsg = {};
    initMsg.type = MessageType::INIT;
    strncpy_s(initMsg.clientInfo.username, username, MAX_NAME_LENGTH - 1);
    strncpy_s(initMsg.clientInfo.hostname, hostname, MAX_NAME_LENGTH - 1);
    send(clientSocket, (char*)&initMsg, sizeof(Message), 0);

    // Создаем поток для обработки команд от сервера
    std::thread commandThread(HandleServerCommands, clientSocket);
    commandThread.detach();

    // Основной цикл для отправки сообщений
    std::string message;
    while (true) {
        std::getline(std::cin, message);
        if (message == "exit") {
            break;
        }
        if (!message.empty()) {
            Message msg;
            msg.type = MessageType::REGULAR;
            strncpy_s(msg.data, message.c_str(), BUFFER_SIZE - 1);
            send(clientSocket, (char*)&msg, sizeof(Message), 0);
        }
    }

    closesocket(clientSocket);
    WSACleanup();
    return 0;
} 