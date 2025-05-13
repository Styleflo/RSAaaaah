#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>

#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    SSL *ssl;
} Client;

static SSL_CTX *ssl_ctx;
static const int server_port = 4433;
static volatile bool server_running = true;
static Client clients[MAX_CLIENTS];
static pthread_t client_threads[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Fonction pour créer le socket et le lier au port d'écoutev*/
static int create_socket()
{
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
            < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

/* Crée le contexte de la connection SSL, c'est-à-dire la methode */
static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/* Configure la verification des certificats pour les clients */
static void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "./ssl/server-cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./ssl/server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*
     * Configure the server to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (!SSL_CTX_load_verify_locations(ctx, "./ssl/ca-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/* Fonction en charge de stdin pour le thread principal */
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

/* Gère chaque client en écoutant ce que le client envoie */
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
        //SSL_write(client->ssl, buffer, bytes);
    }
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;

    /* Create context used by server */
    ssl_ctx = create_context();

    /* Configure server context with appropriate key files */
    configure_server_context(ssl_ctx);

    /* Create server socket; will bind with server port and listen */
    server_skt = create_socket();

    /* Crée un Thread pour prendre en charge les entrées stdin */
    pthread_t stdin_thread;
    if (pthread_create(&stdin_thread, NULL, handle_stdin, NULL) != 0) {
        perror("Erreur lors de la création du thread stdin");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d\n", 4433);

    /*
     * Loop to accept clients.
     * Need to implement timeouts on TCP & SSL connect/read functions
     * before we can catch a CTRL-C and kill the server.
     */
    while (server_running) {
        /* Wait for TCP connection from client */
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_skt = accept(server_skt, (struct sockaddr*)&client_addr, &len);

        if (client_skt < 0) {
            perror("Unable to accept connection");
            continue;
            // exit(EXIT_FAILURE);  comprendre ce que ça fait
        }

        printf("Client TCP connection accepted\n");

        /* Create server SSL structure using newly accepted client socket */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        // if (!SSL_set_fd(ssl, client_skt)) {
        //     ERR_print_errors_fp(stderr);
        //     exit(EXIT_FAILURE);
        // }

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0) {
            printf("Client SSL connection rejected\n");
            ERR_print_errors_fp(stderr);
            close(client_skt);
            SSL_free(ssl);
            // continue;

        } else {
            printf("Client SSL connection accepted\n\n");

            const char *ping_message = "ping";
            if (SSL_write(ssl, ping_message, strlen(ping_message)) <= 0) {
                ERR_print_errors_fp(stderr);
            }

            pthread_mutex_lock(&client_mutex);
            clients[client_count].socket = client_skt;
            clients[client_count].ssl = ssl;
            pthread_create(&client_threads[client_count], NULL, handle_client, &clients[client_count]);
            client_count++;
            pthread_mutex_unlock(&client_mutex);

            printf("New client connected. Total clients: %d\n", client_count);
        }
    }

exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);
    close(server_skt);

    printf("sslecho exiting\n");

    return EXIT_SUCCESS;
}