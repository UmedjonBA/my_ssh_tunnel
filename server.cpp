#include "common.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <map>

struct ClientConnection {
    SOCKET socket;
    ClientInfo info;
    bool isControlled;  // Флаг, указывающий, что клиент находится под управлением
};

std::map<int, ClientConnection> clients;  // Номер клиента -> информация о клиенте
std::mutex clientsMutex;
int nextClientId = 1;

void ListClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    std::cout << "\nConnected clients:\n";
    for (const auto& client : clients) {
        std::cout << "[" << client.first << "] " 
                  << client.second.info.username << "@" 
                  << client.second.info.hostname 
                  << (client.second.isControlled ? " (controlled)" : "")
                  << std::endl;
    }
    std::cout << std::endl;
}

void HandleClient(SOCKET clientSocket, int clientId) {
    char buffer[BUFFER_SIZE] = {};
    Message msg = {};
    ClientConnection& client = clients[clientId];

    // Получаем информацию о клиенте
    int bytesReceived = recv(clientSocket, (char*)&msg, sizeof(Message), 0);
    if (bytesReceived > 0 && msg.type == MessageType::INIT) {
        client.info = msg.clientInfo;
        std::cout << "New client connected [" << clientId << "]: " 
                  << client.info.username << "@" << client.info.hostname << std::endl;
    }

    while (true) {
        bytesReceived = recv(clientSocket, (char*)&msg, sizeof(Message), 0);
        if (bytesReceived <= 0) break;

        if (msg.type == MessageType::COMMAND_OUTPUT) {
            // Выводим результат выполнения команды
            std::cout << "\nOutput from client [" << clientId << "]:\n" << msg.data << std::endl;
        }
        else if (msg.type == MessageType::REGULAR) {
            std::cout << "Message from [" << clientId << "]: " << msg.data << std::endl;
        }
    }

    // Удаляем клиента при отключении
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(clientId);
    }
    std::cout << "Client [" << clientId << "] disconnected" << std::endl;
    closesocket(clientSocket);
}

void ServerCommandHandler() {
    std::string command;
    while (true) {
        std::cout << "\nServer commands:\n"
                  << "list - Show connected clients\n"
                  << "select <id> - Select client to control\n"
                  << "exit - Exit server\n"
                  << "> ";

        std::getline(std::cin, command);

        if (command == "list") {
            ListClients();
        }
        else if (command.substr(0, 6) == "select") {
            try {
                int clientId = std::stoi(command.substr(7));
                std::lock_guard<std::mutex> lock(clientsMutex);
                
                auto it = clients.find(clientId);
                if (it != clients.end()) {
                    // Сбрасываем контроль над всеми клиентами
                    for (auto& client : clients) {
                        client.second.isControlled = false;
                    }
                    
                    // Устанавливаем контроль над выбранным клиентом
                    it->second.isControlled = true;
                    std::cout << "Controlling client [" << clientId << "]\n";
                    
                    // Включаем интерактивный режим
                    Message cmdMsg;
                    cmdMsg.type = MessageType::COMMAND;
                    strncpy_s(cmdMsg.data, "interactive", BUFFER_SIZE - 1);
                    send(it->second.socket, (char*)&cmdMsg, sizeof(Message), 0);
                    
                    // Режим управления клиентом
                    while (true) {
                        std::cout << "Command (or 'back' to return): ";
                        std::string cmd;
                        std::getline(std::cin, cmd);
                        
                        if (cmd == "back") {
                            // Выходим из интерактивного режима
                            cmdMsg.type = MessageType::COMMAND;
                            strncpy_s(cmdMsg.data, "exit_interactive", BUFFER_SIZE - 1);
                            send(it->second.socket, (char*)&cmdMsg, sizeof(Message), 0);
                            break;
                        }
                        
                        cmdMsg.type = MessageType::COMMAND;
                        strncpy_s(cmdMsg.data, cmd.c_str(), BUFFER_SIZE - 1);
                        send(it->second.socket, (char*)&cmdMsg, sizeof(Message), 0);
                    }
                    it->second.isControlled = false;
                }
                else {
                    std::cout << "Client not found\n";
                }
            }
            catch (...) {
                std::cout << "Invalid client ID\n";
            }
        }
        else if (command == "exit") {
            // Закрываем все соединения и выходим
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (const auto& client : clients) {
                // Отправляем команду выхода из интерактивного режима
                Message cmdMsg;
                cmdMsg.type = MessageType::COMMAND;
                strncpy_s(cmdMsg.data, "exit_interactive", BUFFER_SIZE - 1);
                send(client.second.socket, (char*)&cmdMsg, sizeof(Message), 0);
                
                closesocket(client.second.socket);
            }
            clients.clear();
            break;
        }
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(DEFAULT_PORT);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on port " << DEFAULT_PORT << std::endl;

    // Запускаем обработчик команд сервера в отдельном потоке
    std::thread commandThread(ServerCommandHandler);
    commandThread.detach();

    while (true) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        int clientId;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clientId = nextClientId++;
            clients[clientId] = {clientSocket, {}, false};
        }

        std::thread clientThread(HandleClient, clientSocket, clientId);
        clientThread.detach();
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}