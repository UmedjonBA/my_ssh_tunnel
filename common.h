#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

constexpr int DEFAULT_PORT = 12345;
constexpr int BUFFER_SIZE = 1024;
constexpr int MAX_NAME_LENGTH = 256;

// Типы сообщений
enum class MessageType {
    INIT,           // Инициализация клиента
    COMMAND,        // Команда для выполнения
    COMMAND_OUTPUT, // Вывод команды
    REGULAR         // Обычное сообщение
};

struct ClientInfo {
    char username[MAX_NAME_LENGTH];
    char hostname[MAX_NAME_LENGTH];
};

struct Message {
    ClientInfo clientInfo;
    MessageType type;
    char data[BUFFER_SIZE];
}; 
