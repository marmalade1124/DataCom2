#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024
#define ID_SEND_BUTTON 101
#define ID_CHAT_BOX 102
#define ID_MESSAGE_EDIT 103
#define WM_UPDATE_CHAT (WM_USER + 1)

SOCKET server_socket;
HWND hChatBox, hMessageEdit;
unsigned char Key[] = "YourKey"; // Replace with your securely generated key

void logErrors(const char *message) {
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

void handleErrors(void) {
    logErrors("OpenSSL error occurred");
}

void initializeOpenSSL() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void desEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, Key, NULL)) handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    *ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    printf("Encryption successful\n");
}

void desDecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, Key, NULL)) handleErrors();
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    *plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    printf("Decryption successful\n");
}

void appendTextToChatBox(HWND hChatBox, const char *text) {
    int len = GetWindowTextLength(hChatBox);
    SendMessage(hChatBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)text);
}

DWORD WINAPI listenForMessages(LPVOID lpParam) {
    HWND hWnd = (HWND)lpParam;
    char buffer[BUFFER_SIZE];
    unsigned char decrypted_message[BUFFER_SIZE];
    int decrypted_length;
    int recv_size;

    while ((recv_size = recv(server_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[recv_size] = '\0';
        
        desDecrypt((unsigned char *)buffer, recv_size, decrypted_message, &decrypted_length);
        decrypted_message[decrypted_length] = '\0';

        SendMessage(hWnd, WM_UPDATE_CHAT, 0, (LPARAM)strdup((char *)decrypted_message));
    }
    printf("Message listening ended\n");
    return 0;
}

LRESULT CALLBACK WindowsProcedure(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_SEND_BUTTON:
                    char buffer[BUFFER_SIZE];
                    unsigned char encrypted_message[BUFFER_SIZE];
                    int encrypted_length;

                    GetWindowText(hMessageEdit, buffer, BUFFER_SIZE);

                    if (strlen(buffer) > 0) {
                        desEncrypt((unsigned char *)buffer, strlen(buffer), encrypted_message, &encrypted_length);
                        if (send(server_socket, (char *)encrypted_message, encrypted_length, 0) == SOCKET_ERROR) {
                            MessageBox(hWnd, "Failed to send message", "Error", MB_OK | MB_ICONERROR);
                        } else {
                            char chatMessage[BUFFER_SIZE + 20];
                            sprintf(chatMessage, "You: %s\n", buffer);
                            appendTextToChatBox(hChatBox, chatMessage);
                        }

                        SetWindowText(hMessageEdit, "");
                    }
                    printf("Send button clicked\n");
                    break;
            }
            break;
        case WM_UPDATE_CHAT:
            char *receivedMsg = (char *)lParam;
            if (receivedMsg) {
                char chatMessage[BUFFER_SIZE + 20];
                sprintf(chatMessage, "Server: %s\n", receivedMsg);
                appendTextToChatBox(hChatBox, chatMessage);
                free(receivedMsg);
            }
            printf("Message received and displayed\n");
            break;
        case WM_CLOSE:
            closesocket(server_socket);
            WSACleanup();
            DestroyWindow(hWnd);
            printf("Window closed\n");
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            printf("Application ending\n");
            break;
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int main() {
    WSADATA wsaData;
    struct sockaddr_in server;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error Code : %d", WSAGetLastError());
        return 1;
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf("Could not create socket. Error Code : %d", WSAGetLastError());
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(PORT);

    if (connect(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
        closesocket(server_socket);
        printf("Connect failed. Error Code : %d", WSAGetLastError());
        return 1;
    }

    HINSTANCE hInstance = GetModuleHandle(NULL);
    WNDCLASS wc = {0};
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = hInstance;
    wc.lpszClassName = TEXT("ClientWindowClass");
    wc.lpfnWndProc = WindowsProcedure;
    wc.style = CS_HREDRAW | CS_VREDRAW;

    RegisterClass(&wc);

    HWND hWnd = CreateWindow(TEXT("ClientWindowClass"), TEXT("Client"), WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, hInstance, NULL);

    hChatBox = CreateWindow(TEXT("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                            10, 10, 360, 200, hWnd, (HMENU)ID_CHAT_BOX, hInstance, NULL);

    hMessageEdit = CreateWindow(TEXT("EDIT"), NULL, WS_CHILD | WS_VISIBLE | ES_AUTOVSCROLL | ES_MULTILINE,
                                10, 220, 260, 30, hWnd, (HMENU)ID_MESSAGE_EDIT, hInstance, NULL);

    CreateWindow(TEXT("BUTTON"), TEXT("Send"), WS_CHILD | WS_VISIBLE,
                 280, 220, 80, 30, hWnd, (HMENU)ID_SEND_BUTTON, hInstance, NULL);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    CreateThread(NULL, 0, listenForMessages, hWnd, 0, NULL);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    closesocket(server_socket);
    WSACleanup();

    return 0;
}
