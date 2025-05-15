#include <stdio.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include "common.h"

void send_message(Client client, Message* message) {
    message->category = htonl(message->category);
    message->scanner = htonl(message->scanner);
    int len = htonl(strlen(message->payload));

    SSL_write(client.ssl, &message->category, sizeof(message->category));
    SSL_write(client.ssl, &message->scanner, sizeof(message->scanner));
    SSL_write(client.ssl, &len, sizeof(int));
    SSL_write(client.ssl, message->payload, ntohl(len)*sizeof(char));
}


Message* receive_message(SSL* ssl) {
    Message* message = malloc(sizeof(Message));
    int len;

    int bytes = SSL_read(ssl, &message->category, sizeof(message->category));
    if (bytes <= 0) {
        return NULL;
    }
    message->category = ntohl(message->category);

    bytes = SSL_read(ssl, &message->scanner, sizeof(message->scanner));
    if (bytes <= 0) {}
    message->scanner = ntohl(message->scanner);

    bytes = SSL_read(ssl, &len, sizeof(int));
    if (bytes <= 0) {
        return NULL;
    }
    len = ntohl(len);

    message->payload = malloc((len+1)* sizeof(char));

    bytes = SSL_read(ssl, message->payload, len*sizeof(char));
    if (bytes <= 0) {
        printf("erreur à régler\n");
    }
    message->payload[len-1] = '\0';

    return message;
}