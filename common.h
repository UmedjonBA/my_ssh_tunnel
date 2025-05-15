#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define NOMINMAX

// Важно подключать windows.h перед winsock2.h
#include <windows.h> 
#include <winsock2.h>
#include <ws2tcpip.h> // Для inet_pton и других вспомогательных функций
#include <string>      // Для std::string, если используется в структурах (хотя в текущих нет)
// #include <iostream> // Обычно не нужен в общем заголовке

// Линковка с библиотекой Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

const int BUFFER_SIZE = 4096; // Увеличен для вывода команд оболочки
const int DEFAULT_PORT = 12345;

// Информация о клиенте, отправляемая при инициализации
struct ClientInfo {
    char hostname[128]; // Имя хоста клиента
    char username[128]; // Имя пользователя клиента
    // Можно добавить другие поля, например, версию ОС и т.д.
};

// Типы сообщений, которыми обмениваются клиент и сервер
enum class MessageType {
    INIT,                     // Client to Server: Initial info (hostname, username)
    COMMAND,                  // Server to Client: Execute a one-shot command
    COMMAND_OUTPUT,           // Client to Server: Output of the one-shot command
    REGULAR,                  // For simple text messages (optional, not heavily used now)
    ERROR_MSG,                // Generic error message
    START_INTERACTIVE_SHELL,  // Server to Client: Request to start shell (data: "cmd" or "powershell")
    STOP_INTERACTIVE_SHELL,   // Server to Client: Request to stop current interactive shell
    INTERACTIVE_INPUT,        // Server to Client: Send input string to client's active shell
    INTERACTIVE_OUTPUT,       // Client to Server: Send output from client's shell
    SHELL_STARTED_ACK,        // Client to Server: Acknowledgment that shell started successfully
    SHELL_START_FAILED,       // Client to Server: Indicates shell failed to start (data: reason)
    SHELL_STOPPED_ACK,        // Client to Server: Acknowledgment that shell stopped successfully
    TERMINATE_CLIENT          // Server to Client: Command client to terminate itself
};

// Структура сообщения
struct Message {
    MessageType type;
    ClientInfo clientInfo;  // Используется только для типа INIT
    char data[BUFFER_SIZE]; // Полезная нагрузка сообщения (команда, вывод, тип оболочки и т.д.)
    // int dataLength;     // Можно добавить, если data не всегда нуль-терминированная строка
};

// Можно добавить здесь inline вспомогательные функции для создания/обработки сообщений,
// но лучше их выносить в .cpp файлы, если они становятся сложными. 