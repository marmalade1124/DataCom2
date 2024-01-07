#include <winsock2.h>
#include <windows.h>
#include <richedit.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024
#define ID_SEND_BUTTON 101
#define ID_CHAT_BOX 102
#define ID_MESSAGE_EDIT 103
#define WM_UPDATE_CHAT (WM_USER + 1)

SOCKET new_socket;
HWND hChatBox, hMessageEdit;

// Function to generate a random key for encryption
void generate_random_key(char *key, size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (size_t i = 0; i < length; ++i) {
        key[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    key[length] = '\0';
}

// Function to encrypt or decrypt the message using XOR operation
void xor_encrypt_decrypt(char *message, const char *key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        message[i] ^= key[i];
    }
}

// Function to append colored text to the chat box
void appendColoredTextToChatBox(HWND hChatBox, const char *text, COLORREF color) {
    CHARFORMAT cf = { 0 };
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;

    int len = GetWindowTextLength(hChatBox);
    SendMessage(hChatBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(hChatBox, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessage(hChatBox, EM_REPLACESEL, FALSE, (LPARAM)text);
}

// Thread function to listen for incoming encrypted messages
DWORD WINAPI listenForMessages(LPVOID lpParam) {
    HWND hWnd = (HWND)lpParam;
    unsigned int msg_len;

    while (recv(new_socket, (char *)&msg_len, sizeof(msg_len), 0) > 0) {
        char *key = (char *)calloc(msg_len + 1, sizeof(char));
        char *message = (char *)calloc(msg_len + 1, sizeof(char));

        if (key && message) {
            recv(new_socket, key, msg_len, 0);
            recv(new_socket, message, msg_len, 0);
            xor_encrypt_decrypt(message, key, msg_len);
            message[msg_len] = '\0';

            printf("Client Received Key: ");
            for (size_t i = 0; i < msg_len; ++i) {
                printf("%02x", (unsigned char)key[i]);
            }
            printf("\n");

            SendMessage(hWnd, WM_UPDATE_CHAT, 0, (LPARAM)strdup(message));
            free(key);
            free(message);
        }
    }
    return 0;
}

// Main window procedure
LRESULT CALLBACK WindowsProcedure(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_SEND_BUTTON: {
                    char message[BUFFER_SIZE];
                    unsigned int msg_len = GetWindowTextLength(hMessageEdit);
                    GetWindowText(hMessageEdit, message, BUFFER_SIZE);
                    if (msg_len > 0) {
                        char *key = (char *)malloc(msg_len + 1);
                        generate_random_key(key, msg_len);
                        xor_encrypt_decrypt(message, key, msg_len);

                            printf("Server Generated Key: ");
                            for (size_t i = 0; i < msg_len; ++i) {
                                printf("%02x", (unsigned char)key[i]);
                            }
                            printf("\n");

                        send(new_socket, (char *)&msg_len, sizeof(msg_len), 0);
                        send(new_socket, key, msg_len, 0);
                        send(new_socket, message, msg_len, 0);

                        xor_encrypt_decrypt(message, key, msg_len);
                        char chatMessage[BUFFER_SIZE + 20];
                        sprintf(chatMessage, "You: %s\n", message);
                        appendColoredTextToChatBox(hChatBox, chatMessage, RGB(255, 0, 0));
                        SetWindowText(hMessageEdit, "");
                        free(key);
                    }
                    break;
                }
            }
            break;
        case WM_UPDATE_CHAT: {
            char *receivedMsg = (char *)lParam;
            if (receivedMsg) {
                char chatMessage[BUFFER_SIZE + 20];
                sprintf(chatMessage, "Client: %s\n", receivedMsg);
                appendColoredTextToChatBox(hChatBox, chatMessage, RGB(0, 0, 255));
                free(receivedMsg);
            }
            break;
        }
        case WM_CLOSE:
            closesocket(new_socket);
            WSACleanup();
            DestroyWindow(hWnd);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET server_fd;
    struct sockaddr_in address;
    int opt = 1;

    srand((unsigned int)time(NULL));
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    new_socket = accept(server_fd, NULL, NULL);

    HMODULE hRichEdit = LoadLibrary(TEXT("riched20.dll"));
    HINSTANCE hInstance = GetModuleHandle(NULL);
    WNDCLASS wc = { 0 };
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = hInstance;
    wc.lpszClassName = TEXT("myWindowClass");
    wc.lpfnWndProc = WindowsProcedure;
    RegisterClass(&wc);

    HWND hWnd = CreateWindow(TEXT("myWindowClass"), TEXT("Server"), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 
                                400, 300, NULL, NULL, hInstance, NULL);

    hChatBox = CreateWindowEx(0, TEXT("RichEdit20W"), NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 
                            10, 10, 360, 200, hWnd, (HMENU)ID_CHAT_BOX, hInstance, NULL);

    hMessageEdit = CreateWindow(TEXT("EDIT"), NULL, WS_CHILD | WS_VISIBLE | ES_AUTOVSCROLL | ES_MULTILINE, 
                            10, 220, 260, 30, hWnd, (HMENU)ID_MESSAGE_EDIT, hInstance, NULL);
                            
    CreateWindow(TEXT("BUTTON"), TEXT("Send"), WS_CHILD | WS_VISIBLE, 
                            280, 220, 80, 30, hWnd, (HMENU)ID_SEND_BUTTON, hInstance, NULL);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    CreateThread(NULL, 0, listenForMessages, hWnd, 0, NULL);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    closesocket(server_fd);
    WSACleanup();

    return 0;
}
