#ifndef COMMON_H
#define COMMON_H

#include <openssl/ssl.h>
#include <stdbool.h>
#define BUFFER_SIZE 1024

typedef enum {
    COMMAND = 1,
    OTHER = 2,
    RESULT
} CategoryID;

typedef enum {
    NMAP = 1,
    ZAP = 2,
    NIKTO = 3,
    GENERIC_MESSAGE = 99
} ScannerID;

typedef struct {
    int id;
    int socket;
    SSL *ssl;
} Client;

typedef struct {
    CategoryID category;
    ScannerID scanner;
    char* payload;
} Message;

/* Fonctions déclarées dans common.c */
void send_message(Client client, Message *message);
Message* receive_message(SSL* ssl);

#endif /* COMMON_H */
