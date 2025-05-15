#include "common.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <string>
#include <atomic>
#include <limits> // Required for std::numeric_limits

struct ClientConnection {
    SOCKET socket;
    ClientInfo info;
    bool isInInteractiveMode; // Флаг, что этот клиент сейчас в интерактивной сессии с сервером
    std::string currentShellType; // "cmd", "powershell" или пустая строка
};

std::map<int, ClientConnection> clients;
std::mutex clientsMutex;
std::atomic<int> nextClientId(1);
std::atomic<bool> g_serverRunning(true); // Controls the main accept loop
SOCKET g_listenSocket = INVALID_SOCKET; // Global handle for the listening socket

// ID клиента, который в данный момент управляется интерактивной оболочкой с сервера.
// -1 означает, что ни один клиент не находится в этом режиме.
int g_interactiveClientTargetId = -1;

void ListClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    std::cout << "\n--- Connected Clients ---" << std::endl;
    if (clients.empty()) {
        std::cout << "No clients connected." << std::endl;
    } else {
        for (const auto& pair : clients) {
            std::cout << "ID: [" << pair.first << "] "
                      << pair.second.info.username << "@" << pair.second.info.hostname;
            if (pair.second.isInInteractiveMode) {
                std::cout << " (Interactive: " << pair.second.currentShellType << ")";
            }
            // Дополнительно указываем, если сервер УПРАВЛЯЕТ этим клиентом в данный момент
            if (pair.first == g_interactiveClientTargetId) {
                std::cout << " <-- SERVER CONTROLLING";
            }
            std::cout << std::endl;
        }
    }
    std::cout << "-------------------------" << std::endl;
}

void HandleClient(SOCKET clientSocket, int clientId) {
    // char buffer[BUFFER_SIZE] = {}; // Не используется напрямую в этой новой версии
    Message msg = {};
    ClientConnection* currentClientConnection = nullptr;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        // Получаем указатель на ClientConnection, если он еще существует
        auto it = clients.find(clientId);
        if (it != clients.end()) {
            currentClientConnection = &it->second;
        } else {
            // Клиент мог быть удален до того, как этот поток начал полноценную работу
            std::cout << "[Server] Client [" << clientId << "] not found upon thread start. Likely already disconnected." << std::endl;
            closesocket(clientSocket); // Закрываем сокет, если он еще не был
            return;
        }
    }

    // Первое сообщение от клиента должно быть INIT
    int bytesReceived = recv(clientSocket, (char*)&msg, sizeof(Message), 0);
    if (bytesReceived > 0 && msg.type == MessageType::INIT) {
        currentClientConnection->info = msg.clientInfo;
        std::cout << "[Server] Client [" << clientId << "] initialized: " 
                  << currentClientConnection->info.username << "@" 
                  << currentClientConnection->info.hostname << std::endl;
    } else {
        std::cout << "[Server] Client [" << clientId << "] failed to send INIT or disconnected before INIT. Error: " << WSAGetLastError() << std::endl;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients.erase(clientId);
             if (clientId == g_interactiveClientTargetId) { // Сбрасываем, если это был интерактивный клиент
                g_interactiveClientTargetId = -1;
            }
        }
        closesocket(clientSocket);
        return;
    }

    while (true) {
        ZeroMemory(&msg, sizeof(Message)); // Очищаем структуру сообщения перед recv
        bytesReceived = recv(clientSocket, (char*)&msg, sizeof(Message), 0);
        
        if (bytesReceived == SOCKET_ERROR) {
            std::cout << "[Server] Recv failed for client [" << clientId << "] with error: " << WSAGetLastError() << std::endl;
            break; // Выходим из цикла при ошибке сокета
        }
        if (bytesReceived == 0) {
            std::cout << "[Server] Client [" << clientId << "] gracefully closed connection." << std::endl;
            break; // Клиент закрыл соединение
        }

        // Обработка сообщений от клиента
        switch (msg.type) {
            case MessageType::COMMAND_OUTPUT: // Вывод от одноразовой команды
                std::cout << "\n[Server] Output from client [" << clientId << "] (One-shot Command):\n"
                          << msg.data << std::endl;
                break;
            case MessageType::INTERACTIVE_OUTPUT: // Вывод из интерактивной оболочки
                // Выводим только если этот клиент находится под интерактивным управлением СЕРВЕРА
                if (clientId == g_interactiveClientTargetId) {
                    std::cout << msg.data; // Вывод как есть, без доп. префиксов сервера
                    fflush(stdout); // Важно для немедленного отображения в консоли
                }
                break;
            case MessageType::SHELL_STARTED_ACK:
                std::cout << "\n[Server] Client [" << clientId << "] ACK: Shell started - " << msg.data << std::endl;
                if (clientId == g_interactiveClientTargetId) {
                    if (std::string(msg.data) == "OK") {
                        // currentClientConnection->isInInteractiveMode уже true
                        // currentClientConnection->currentShellType уже установлен
                        std::cout << "Enter commands for client [" << clientId << "] (or '!exit_shell' to stop):\n> ";
                        fflush(stdout);
                    } else {
                        // Ошибка на клиенте, сбрасываем интерактивный режим на сервере
                        std::cout << "[Server] Shell start acknowledged by client [" << clientId << "] but with an issue: " << msg.data << std::endl;
                        g_interactiveClientTargetId = -1;
                        currentClientConnection->isInInteractiveMode = false;
                        currentClientConnection->currentShellType = "";
                    }
                } else {
                     std::cout << "[Server] Received SHELL_STARTED_ACK from non-interactive target client [" << clientId << "]. Ignoring." << std::endl;
                }
                break;
            case MessageType::SHELL_START_FAILED:
                std::cout << "\n[Server] Client [" << clientId << "] NACK: Shell start FAILED - " << msg.data << std::endl;
                if (clientId == g_interactiveClientTargetId) {
                    g_interactiveClientTargetId = -1;
                    currentClientConnection->isInInteractiveMode = false;
                    currentClientConnection->currentShellType = "";
                }
                 // Можно добавить вывод предыдущего серверного приглашения, если нужно
                break;
            case MessageType::SHELL_STOPPED_ACK:
                 std::cout << "\n[Server] Client [" << clientId << "] ACK: Shell stopped - " << msg.data << std::endl;
                 // Клиент подтвердил остановку. isInInteractiveMode и currentShellType уже должны быть сброшены
                 // сервером при отправке команды STOP_INTERACTIVE_SHELL. g_interactiveClientTargetId тоже.
                 // Здесь просто логируем.
                 if (std::string(msg.data) != "OK") {
                     std::cout << "[Server] Shell stop acknowledged by client [" << clientId << "] but with an issue: " << msg.data << std::endl;
                 }
                 // Если вдруг это был интерактивный клиент, а сервер еще не сбросил, подстраховка:
                 if (clientId == g_interactiveClientTargetId) {
                     std::cout << "[Server] Warning: SHELL_STOPPED_ACK received for client [" << clientId << "] still marked as interactive target. Resetting." << std::endl;
                     g_interactiveClientTargetId = -1; 
                 }
                 // Флаги клиента (isInInteractiveMode, currentShellType) должны были быть сброшены в ServerCommandHandler
                 // при отправке STOP_INTERACTIVE_SHELL. Если клиент шлет это сам по себе, это может быть неожиданно.
                 currentClientConnection->isInInteractiveMode = false; 
                 currentClientConnection->currentShellType = "";
                 break;
            case MessageType::REGULAR: // Обычные сообщения от клиента (если мы их поддерживаем)
                 std::cout << "\n[Server] Message from client [" << clientId << "]: " << msg.data << std::endl;
                 break;
            default:
                 std::cout << "\n[Server] Client [" << clientId << "] sent unknown message type: " << static_cast<int>(msg.type) << std::endl;
                 break;
        }
    }

    // Клиент отключился (цикл recv прерван)
    std::cout << "[Server] Cleaning up for client [" << clientId << "]: " 
              << (currentClientConnection ? currentClientConnection->info.username : "<unknown>") << "@" 
              << (currentClientConnection ? currentClientConnection->info.hostname : "<unknown>") << std::endl;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(clientId);
        if (clientId == g_interactiveClientTargetId) {
            g_interactiveClientTargetId = -1; // Сбрасываем, если управляемый клиент отключился
            std::cout << "[Server] Interactive session with client [" << clientId << "] terminated due to disconnect." << std::endl;
            // Здесь можно добавить вывод обычного приглашения сервера, если ServerCommandHandler его не выводит сам
            // std::cout << "\n[Server] Commands: ... \n> "; fflush(stdout);
        }
    }
    closesocket(clientSocket);
    // std::cout << "Client [" << clientId << "] disconnected" << std::endl; // Заменено более подробным сообщением выше
}

// Обработчик команд сервера
void ServerCommandHandler() {
    std::string lineInput;
    // Buffer for messages, ensure it's clean for each new message.
    Message msg_buffer; 

    while (g_serverRunning.load()) { // Loop as long as the server is intended to run
        if (!g_serverRunning.load()) break; // Check again before blocking on getline

        if (g_interactiveClientTargetId != -1) {
            // In interactive shell mode for g_interactiveClientTargetId.
            // Prompt is handled by HandleClient after SHELL_STARTED_ACK.
            // Server can optionally show a simple prompt like "shell> " if desired,
            // but for cleaner client output, it's often better to show nothing here.
        } else {
            std::cout << "\n[Server] Commands: list | select <id> <cmd> | remote_shell <id> <shell_type> | say <id> <message> | !exit_shell | quit\n> ";
            fflush(stdout);
        }

        if (!std::getline(std::cin, lineInput)) {
            if (std::cin.eof()) {
                std::cout << "[Server] EOF detected on command input. Initiating shutdown..." << std::endl;
                if (g_serverRunning.load()) { // Ensure shutdown is only initiated once
                    g_serverRunning.store(false); // Signal main loop and this loop to stop

                    std::cout << "[Server] Notifying clients and closing connections..." << std::endl;
                    {
                        std::lock_guard<std::mutex> lock(clientsMutex);
                        for (auto const& [id, conn] : clients) {
                            if (conn.isInInteractiveMode) {
                                ZeroMemory(&msg_buffer, sizeof(Message));
                                msg_buffer.type = MessageType::STOP_INTERACTIVE_SHELL;
                                send(conn.socket, (char*)&msg_buffer, sizeof(Message), 0);
                                // Brief pause for client to process, optional
                                // std::this_thread::sleep_for(std::chrono::milliseconds(50)); 
                            }
                            ZeroMemory(&msg_buffer, sizeof(Message));
                            msg_buffer.type = MessageType::TERMINATE_CLIENT;
                            send(conn.socket, (char*)&msg_buffer, sizeof(Message), 0);
                            shutdown(conn.socket, SD_BOTH);
                            closesocket(conn.socket);
                        }
                        clients.clear();
                        if (g_interactiveClientTargetId != -1) {
                             g_interactiveClientTargetId = -1; // Clear active shell target
                        }
                    }
                    std::cout << "[Server] All client connections closed by command handler." << std::endl;
                    
                    if (g_listenSocket != INVALID_SOCKET) {
                        std::cout << "[Server] Command handler closing listening socket to unblock main." << std::endl;
                        closesocket(g_listenSocket);
                        g_listenSocket = INVALID_SOCKET; // Mark as closed
                    }
                }
            } else if (std::cin.fail() || std::cin.bad()) {
                std::cerr << "[Server] Error reading command input. Resetting cin state." << std::endl;
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                continue;
            }
            break; // Exit loop on EOF or critical cin error
        }

        if (!g_serverRunning.load()) break; // Check after getline, if shutdown was initiated elsewhere

        if (lineInput.empty() && g_interactiveClientTargetId != -1) {
            // If in interactive mode and user hits Enter, send newline as input.
            // (Handled below by sending lineInput directly, which will be just newline if empty)
        } else if (lineInput.empty()) {
            continue; // In normal mode, skip empty input
        }

        if (g_interactiveClientTargetId != -1) {
            // ----- INTERACTIVE SHELL MODE ----- 
            if (lineInput == "!exit_shell") {
                std::cout << "[Server] Requesting client [" << g_interactiveClientTargetId << "] to stop interactive shell..." << std::endl;
                ZeroMemory(&msg_buffer, sizeof(Message));
                msg_buffer.type = MessageType::STOP_INTERACTIVE_SHELL;
                
                std::lock_guard<std::mutex> lock(clientsMutex);
                auto it = clients.find(g_interactiveClientTargetId);
                if (it != clients.end()) {
                    send(it->second.socket, (char*)&msg_buffer, sizeof(Message), 0);
                    it->second.isInInteractiveMode = false;
                    it->second.currentShellType = "";
                } else {
                     std::cout << "[Server] Client [" << g_interactiveClientTargetId << "] not found to stop shell (already disconnected?)." << std::endl;
                }
                g_interactiveClientTargetId = -1; 
            } else {
                ZeroMemory(&msg_buffer, sizeof(Message));
                msg_buffer.type = MessageType::INTERACTIVE_INPUT;
                std::string commandWithNewline = lineInput + "\n"; 
                strncpy_s(msg_buffer.data, commandWithNewline.c_str(), BUFFER_SIZE - 1);
                msg_buffer.data[BUFFER_SIZE - 1] = '\0';
                
                std::lock_guard<std::mutex> lock(clientsMutex);
                auto it = clients.find(g_interactiveClientTargetId);
                if (it != clients.end()) {
                    if(send(it->second.socket, (char*)&msg_buffer, sizeof(Message), 0) == SOCKET_ERROR) {
                        std::cerr << "[Server] Failed to send INTERACTIVE_INPUT to client [" << g_interactiveClientTargetId << "]. Error: " << WSAGetLastError() << std::endl;
                        // Optionally, treat as disconnect and exit interactive mode
                    }
                } else {
                    std::cout << "[Server] Interactive client [" << g_interactiveClientTargetId << "] disconnected. Exiting interactive mode." << std::endl;
                    g_interactiveClientTargetId = -1; 
                }
            }
        } else {
            // ----- NORMAL SERVER MODE ----- 
            if (lineInput == "list") {
                ListClients();
            } else if (lineInput.rfind("select ", 0) == 0) {
                try {
                    size_t firstSpace = lineInput.find(' ');
                    size_t secondSpace = lineInput.find(' ', firstSpace + 1);
                    if (firstSpace == std::string::npos || secondSpace == std::string::npos) {
                        std::cout << "[Server] Invalid select format. Use: select <id> <command_to_run>" << std::endl; continue;
                    }
                    int clientId = std::stoi(lineInput.substr(firstSpace + 1, secondSpace - (firstSpace + 1)));
                    std::string cmdToRun = lineInput.substr(secondSpace + 1);
                    if (cmdToRun.empty()) {
                         std::cout << "[Server] Command cannot be empty for select." << std::endl; continue;
                    }

                    ZeroMemory(&msg_buffer, sizeof(Message));
                    msg_buffer.type = MessageType::COMMAND;
                    strncpy_s(msg_buffer.data, cmdToRun.c_str(), BUFFER_SIZE - 1);
                    msg_buffer.data[BUFFER_SIZE - 1] = '\0';
                    
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    auto it = clients.find(clientId);
                    if (it != clients.end()) {
                         if (it->second.isInInteractiveMode) {
                            std::cout << "[Server] Client [" << clientId << "] is currently in an interactive session. Cannot send one-shot command." << std::endl;
                        } else {
                            if(send(it->second.socket, (char*)&msg_buffer, sizeof(Message), 0) == SOCKET_ERROR){
                                std::cerr << "[Server] Failed to send COMMAND to client [" << clientId << "]. Error: " << WSAGetLastError() << std::endl;
                            } else {
                                std::cout << "[Server] Sent one-shot command to client [" << clientId << "]: " << cmdToRun << std::endl;
                            }
                        }
                    } else {
                        std::cout << "[Server] Client ID [" << clientId << "] not found." << std::endl;
                    }
                } catch (const std::invalid_argument& ia) {
                    std::cout << "[Server] Invalid client ID for select: " << ia.what() << std::endl;
                } catch (const std::out_of_range& oor) {
                    std::cout << "[Server] Client ID for select out of range: " << oor.what() << std::endl;
                }
            } else if (lineInput.rfind("remote_shell ", 0) == 0) {
                try {
                    size_t firstSpace = lineInput.find(' ');
                    size_t secondSpace = lineInput.find(' ', firstSpace + 1);
                    if (firstSpace == std::string::npos || secondSpace == std::string::npos) {
                        std::cout << "[Server] Invalid remote_shell format. Use: remote_shell <id> <cmd|powershell>" << std::endl; continue;
                    }
                    int clientId = std::stoi(lineInput.substr(firstSpace + 1, secondSpace - (firstSpace + 1)));
                    std::string shellType = lineInput.substr(secondSpace + 1);

                    if (shellType != "cmd" && shellType != "powershell") {
                        std::cout << "[Server] Invalid shell type. Use 'cmd' or 'powershell'." << std::endl; continue;
                    }

                    std::lock_guard<std::mutex> lock(clientsMutex);
                    auto it = clients.find(clientId);
                    if (it != clients.end()) {
                        if (g_interactiveClientTargetId != -1 && g_interactiveClientTargetId != clientId) {
                            std::cout << "[Server] Another client (ID: " << g_interactiveClientTargetId << ") is already in an interactive session. Use '!exit_shell' first." << std::endl;
                        } else if (g_interactiveClientTargetId == clientId) {
                            std::cout << "[Server] Client [" << clientId << "] is ALREADY the interactive target with shell " << it->second.currentShellType << "." << std::endl;
                        } else if (it->second.isInInteractiveMode) {
                             std::cout << "[Server] Client [" << clientId << "] is in an interactive session, but not targeted by server. Use '!exit_shell' on current target or wait." << std::endl;
                        } else {
                            ZeroMemory(&msg_buffer, sizeof(Message));
                            msg_buffer.type = MessageType::START_INTERACTIVE_SHELL;
                            strncpy_s(msg_buffer.data, shellType.c_str(), BUFFER_SIZE - 1);
                            msg_buffer.data[BUFFER_SIZE - 1] = '\0';
                            if(send(it->second.socket, (char*)&msg_buffer, sizeof(Message), 0) == SOCKET_ERROR){
                                 std::cerr << "[Server] Failed to send START_INTERACTIVE_SHELL to client [" << clientId << "]. Error: " << WSAGetLastError() << std::endl;
                            } else {
                                std::cout << "[Server] Requesting client [" << clientId << "] to start " << shellType << "..." << std::endl;
                                g_interactiveClientTargetId = clientId;
                                it->second.isInInteractiveMode = true; 
                                it->second.currentShellType = shellType;
                            }
                        }
                    } else {
                        std::cout << "[Server] Client ID [" << clientId << "] not found for remote_shell." << std::endl;
                    }
                } catch (const std::invalid_argument& ia) {
                    std::cout << "[Server] Invalid client ID for remote_shell: " << ia.what() << std::endl;
                } catch (const std::out_of_range& oor) {
                    std::cout << "[Server] Client ID for remote_shell out of range: " << oor.what() << std::endl;
                }
            } else if (lineInput.rfind("say ", 0) == 0) { // say <id> <message_text>
                try {
                    size_t firstSpace = lineInput.find(' ');
                    size_t secondSpace = lineInput.find(' ', firstSpace + 1);
                    if (firstSpace == std::string::npos || secondSpace == std::string::npos) {
                        std::cout << "[Server] Invalid say format. Use: say <id> <message_text>" << std::endl; continue;
                    }
                    int clientId = std::stoi(lineInput.substr(firstSpace + 1, secondSpace - (firstSpace + 1)));
                    std::string messageText = lineInput.substr(secondSpace + 1);
                    if (messageText.empty()) {
                         std::cout << "[Server] Message text cannot be empty for say command." << std::endl; continue;
                    }

                    ZeroMemory(&msg_buffer, sizeof(Message));
                    msg_buffer.type = MessageType::REGULAR;
                    strncpy_s(msg_buffer.data, messageText.c_str(), BUFFER_SIZE - 1);
                    msg_buffer.data[BUFFER_SIZE - 1] = '\0';
                    
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    auto it = clients.find(clientId);
                    if (it != clients.end()) {
                        if(send(it->second.socket, (char*)&msg_buffer, sizeof(Message), 0) == SOCKET_ERROR) {
                            std::cerr << "[Server] Failed to send REGULAR message to client [" << clientId << "]. Error: " << WSAGetLastError() << std::endl;
                        } else {
                            std::cout << "[Server] Sent message to client [" << clientId << "]: " << messageText << std::endl;
                        }
                    } else {
                        std::cout << "[Server] Client ID [" << clientId << "] not found for say command." << std::endl;
                    }
                } catch (const std::invalid_argument& ia) {
                    std::cout << "[Server] Invalid client ID for say: " << ia.what() << std::endl;
                } catch (const std::out_of_range& oor) {
                    std::cout << "[Server] Client ID for say out of range: " << oor.what() << std::endl;
                }
            } else if (lineInput == "!exit_shell") {
                std::cout << "[Server] Command '!exit_shell' issued in non-interactive mode. No active server-side shell to exit." << std::endl;
            } else if (lineInput == "quit" || lineInput == "exit") {
                std::cout << "[Server] Shutdown command received. Initiating shutdown..." << std::endl;
                if (g_serverRunning.load()) { // Ensure shutdown is only initiated once by this command
                    g_serverRunning.store(false); // Signal main loop and this loop to stop

                    std::cout << "[Server] Notifying clients and closing connections..." << std::endl;
                    {
                        std::lock_guard<std::mutex> lock(clientsMutex);
                        // Create a temporary list of client IDs to iterate over, 
                        // as clients map might be modified if a client disconnects during this process (though less likely here)
                        std::vector<int> client_ids;
                        for(auto const& [id, conn_val] : clients) client_ids.push_back(id);

                        for (int id : client_ids) {
                            auto it = clients.find(id);
                            if (it == clients.end()) continue; // Client might have disconnected
                            
                            const auto& conn = it->second; // Use const auto&

                            if (conn.isInInteractiveMode) {
                                ZeroMemory(&msg_buffer, sizeof(Message));
                                msg_buffer.type = MessageType::STOP_INTERACTIVE_SHELL;
                                send(conn.socket, (char*)&msg_buffer, sizeof(Message), 0);
                                // std::this_thread::sleep_for(std::chrono::milliseconds(50)); 
                            }
                            ZeroMemory(&msg_buffer, sizeof(Message));
                            msg_buffer.type = MessageType::TERMINATE_CLIENT;
                            send(conn.socket, (char*)&msg_buffer, sizeof(Message), 0);
                            shutdown(conn.socket, SD_BOTH);
                            closesocket(conn.socket);
                        }
                        clients.clear();
                        if (g_interactiveClientTargetId != -1) {
                             g_interactiveClientTargetId = -1;
                        }
                    }
                     std::cout << "[Server] All client connections closed by command handler." << std::endl;
                    
                    if (g_listenSocket != INVALID_SOCKET) {
                        std::cout << "[Server] Command handler closing listening socket to unblock main." << std::endl;
                        closesocket(g_listenSocket);
                        g_listenSocket = INVALID_SOCKET; // Mark as closed
                    }
                }
                break; // Exit command handler loop
            } else {
                std::cout << "[Server] Unknown command or invalid format: " << lineInput << std::endl;
            }
        }
    }
    std::cout << "[Server] Command handler thread exiting." << std::endl;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Server] Failed to initialize Winsock. Error Code: " << WSAGetLastError() << std::endl;
        return 1;
    }
    std::cout << "[Server] Winsock initialized successfully." << std::endl;

    // SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Original
    g_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Use global
    if (g_listenSocket == INVALID_SOCKET) {
        std::cerr << "[Server] Failed to create socket. Error Code: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }
    std::cout << "[Server] Socket created successfully." << std::endl;

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(DEFAULT_PORT);

    if (bind(g_listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[Server] Bind failed. Error Code: " << WSAGetLastError() << std::endl;
        closesocket(g_listenSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "[Server] Socket bound successfully to port " << DEFAULT_PORT << std::endl;

    if (listen(g_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[Server] Listen failed. Error Code: " << WSAGetLastError() << std::endl;
        closesocket(g_listenSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "[Server] is listening on port " << DEFAULT_PORT << "..." << std::endl;

    std::thread serverCommandsThread(ServerCommandHandler);

    std::cout << "[Server] Main accept loop started. Waiting for connections..." << std::endl;
    while (g_serverRunning.load()) {
        SOCKET clientSocket = accept(g_listenSocket, nullptr, nullptr);
        if (!g_serverRunning.load()) { // Check flag immediately after accept unblocks
             if (clientSocket != INVALID_SOCKET) { // If a connection was accepted just before shutdown
                std::cout << "[Server] Connection accepted during shutdown. Closing it." << std::endl;
                closesocket(clientSocket);
            }
            break; // Exit loop if server is stopping
        }

        if (clientSocket == INVALID_SOCKET) {
            int errorCode = WSAGetLastError();
            if (g_serverRunning.load()) { // Only log as error if not shutting down
                 // WSAEINTR can occur if a signal interrupts accept, not necessarily an error.
                 // WSAENOTSOCK or WSAEINVAL means the listening socket was likely closed.
                if (errorCode == WSAENOTSOCK || errorCode == WSAEINVAL) {
                     std::cout << "[Server] Listening socket closed (Error: " << errorCode << "). Assuming shutdown." << std::endl;
                     g_serverRunning.store(false); // Ensure flag is set if socket closed externally
                } else if (errorCode != WSAEINTR) { // Log other errors
                    std::cerr << "[Server] Accept failed with error: " << errorCode << std::endl;
                }
            }
            // If g_serverRunning is false, or error was WSAENOTSOCK/WSAEINVAL indicating closed socket, break
            if (!g_serverRunning.load() || errorCode == WSAENOTSOCK || errorCode == WSAEINVAL) {
                break;
            }
            continue; // For recoverable errors like WSAEINTR when not shutting down
        }

        int newClientId = nextClientId++; 
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients[newClientId] = {clientSocket, {}, false, ""};
        }
        std::cout << "[Server] Client [" << newClientId << "] connected. Socket: " << clientSocket << std::endl;
        std::thread clientHandlerThread(HandleClient, clientSocket, newClientId);
        clientHandlerThread.detach();
    }

    std::cout << "[Server] Shutting down main accept loop." << std::endl;
    
    if (serverCommandsThread.joinable()) {
        std::cout << "[Server] Waiting for command handler thread to finish..." << std::endl;
        serverCommandsThread.join(); 
    } else {
        std::cout << "[Server] Command handler thread not joinable (already finished or detached)." << std::endl;
    }

    if (g_listenSocket != INVALID_SOCKET) { // Ensure not to close an already closed socket by cmd handler
        std::cout << "[Server] Closing listening socket in main." << std::endl;
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
    }
    WSACleanup();
    std::cout << "[Server] Winsock cleaned up. Application terminated." << std::endl;
    return 0;
} 