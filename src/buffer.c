
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

#define PORT 4433
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    SSL *ssl;
} Client;

static SSL_CTX *create_context();
static void configure_context(SSL_CTX *ctx);
static void *handle_client(void *arg);
static void *handle_stdin(void *arg);
static int create_socket(int port);

static SSL_CTX *ssl_ctx;
static Client clients[MAX_CLIENTS];
static pthread_t client_threads[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

int main() {
    signal(SIGPIPE, SIG_IGN);

    ssl_ctx = create_context();
    configure_context(ssl_ctx);

    int server_socket = create_socket(PORT);
    pthread_t stdin_thread;
    pthread_create(&stdin_thread, NULL, handle_stdin, NULL);

    printf("Server listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);

        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &len);
        if (client_socket < 0) {
            perror("Unable to accept connection");
            continue;
        }

        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            SSL_free(ssl);
            continue;
        }

        pthread_mutex_lock(&client_mutex);
        clients[client_count].socket = client_socket;
        clients[client_count].ssl = ssl;
        pthread_create(&client_threads[client_count], NULL, handle_client, &clients[client_count]);
        client_count++;
        pthread_mutex_unlock(&client_mutex);

        printf("New client connected. Total clients: %d\n", client_count);
    }

    close(server_socket);
    SSL_CTX_free(ssl_ctx);
    return 0;
}

static SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

static void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "./ssl/server-cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./ssl/server-key.pem", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_load_verify_locations(ctx, "./ssl/ca-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

static void *handle_client(void *arg) {
    Client *client = (Client *)arg;
    char buffer[BUFFER_SIZE];

    while (1) {
        int bytes = SSL_read(client->ssl, buffer, sizeof(buffer));
        if (bytes <= 0) {
            perror("Client disconnected or SSL error");
            SSL_shutdown(client->ssl);
            SSL_free(client->ssl);
            close(client->socket);
            pthread_exit(NULL);
        }

        buffer[bytes] = 0;
        printf("Client: %s", buffer);
        SSL_write(client->ssl, buffer, bytes);
    }
}

static void *handle_stdin(void *arg) {
    char buffer[BUFFER_SIZE];

    while (1) {
        fgets(buffer, sizeof(buffer), stdin);

        pthread_mutex_lock(&client_mutex);
        for (int i = 0; i < client_count; i++) {
            SSL_write(clients[i].ssl, buffer, strlen(buffer));
        }
        pthread_mutex_unlock(&client_mutex);
    }
}

static int create_socket(int port) {
    int s;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}
