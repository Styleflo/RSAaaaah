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
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include <string.h>
#include <netdb.h>
#include <ifaddrs.h>


// static const int server_port = 4433;

static int create_socket()
{
    int s;
    struct sockaddr_in serv_addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    return s;
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void configure_client_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "./ssl/client-cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./ssl/client-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_load_verify_locations(ctx, "./ssl/ca-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int get_local_ip(char *buffer, size_t buffer_size) {
    struct ifaddrs *ifaddr, *ifa;
    int family;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // On cherche uniquement les adresses IPv4
        if (family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), buffer, buffer_size, NULL, 0, NI_NUMERICHOST) == 0) {
                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}


#define BUFFERSIZE 1024
int main(int argc, char **argv)
{

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int client_skt;

    /* used by fgets */
    char buffer[BUFFERSIZE];

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_ip = NULL;
    char *rem_server_port = NULL;

    struct sockaddr_in addr;

    signal(SIGPIPE, SIG_IGN);


    rem_server_ip = argv[4];
    rem_server_port = argv[5];

    /* convertir le port en int/long */
    long port = strtol(rem_server_port, NULL, 10);

    /* Create context used by client */
    ssl_ctx = create_context();

    /* Configure client context so we verify the server correctly */
    configure_client_context(ssl_ctx);

    /* Create "bare" socket */
    client_skt = create_socket();

    /* Set up connect address */
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(port);

    /* Do TCP connect with server */
    if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        goto exit;
    }

    /* Create client SSL structure using dedicated client socket */
    ssl = SSL_new(ssl_ctx);
    if (!SSL_set_fd(ssl, client_skt)) {
        ERR_print_errors_fp(stderr);
        goto exit;
    }
    /* Set hostname for SNI */
    SSL_set_tlsext_host_name(ssl, rem_server_ip);
    /* Configure server hostname check */
    if (!SSL_set1_host(ssl, rem_server_ip)) {
        ERR_print_errors_fp(stderr);
        goto exit;
    }


    /* Now do SSL connect with server */
    if (SSL_connect(ssl) == 1) {

        rxlen = SSL_read(ssl, rxbuf, rxcap);
        if (rxlen <= 0) {
            printf("SSL connection refused due to invalid certification\n");
            goto exit;
        }

        /* Loop to send input from keyboard */
        while (true) {
            Message* message = receive_message(ssl);
            if (message == NULL) {
                goto exit;
            }

            if (message->category == 1) {
                char command[BUFFER_SIZE];
                memset(command, 0, sizeof(command));

                if (message->scanner == 1) {
                    snprintf(command, sizeof(command), "nmap %s", message->payload);

                    FILE* fichier = popen(command, "r");
                    if (fichier != NULL) {

                        int buf = htonl(RESULT);
                        int n;
                        SSL_write(ssl, &buf, sizeof(int));

                        while ((n = fread(buffer, 1, sizeof(buffer), fichier)) > 0) {
                            if (SSL_write(ssl, buffer, n) < 0) {
                                perror("write");
                                break;
                            }
                        }
                        pclose(fichier);
                    } else {
                        perror("popen");
                    }
                }

                if (message->scanner == 2) {  // 2 = OWASP ZAP

                    // Vérifier si ZAP est déjà lancé
                    FILE* zap_check = popen("ps aux | grep '[z]ap.sh'", "r");
                    if (zap_check) {
                        if (fgets(buffer, sizeof(buffer), zap_check) == NULL) {
                            printf("OWASP ZAP non détecté, démarrage...\n");
                            system("zap.sh -daemon -port 8080 &");
                            printf("OWASP ZAP démarré en mode daemon.\n");

                            // Attendre que ZAP soit prêt
                            int is_ready = 0;
                            while (!is_ready) {
                                FILE* curl_check = popen("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080", "r");
                                if (curl_check) {
                                    char status[4];
                                    fgets(status, sizeof(status), curl_check);
                                    if (strncmp(status, "200", 3) == 0) {
                                        is_ready = 1;
                                    } else {
                                        printf("En attente de l'initialisation de ZAP...\n");
                                        sleep(2);  // Attente avant le prochain check
                                    }
                                    pclose(curl_check);
                                }
                            }
                            printf("OWASP ZAP est prêt.\n");
                        } else {
                            printf("OWASP ZAP déjà démarré.\n");
                        }
                        pclose(zap_check);
                    }

                    // Lancer le scan via l'URL contenue dans le payload
                    snprintf(command, sizeof(command), "curl '%s'", message->payload);

                    FILE* fichier = popen(command, "r");
                    if (fichier != NULL) {
                        int buf = htonl(RESULT);
                        SSL_write(ssl, &buf, sizeof(int));

                        int n;
                        while ((n = fread(buffer, 1, sizeof(buffer), fichier)) > 0) {
                            if (SSL_write(ssl, buffer, n) < 0) {
                                perror("write");
                                break;
                            }
                        }
                        pclose(fichier);
                    } else {
                        perror("popen");
                    }
                }

                if (message->scanner == 3) {  // 3 = Nikto

                    // Construction de la commande Nikto
                    snprintf(command, sizeof(command), "nikto %s", message->payload);

                    // Exécution de la commande avec popen
                    FILE* fichier = popen(command, "r");
                    if (fichier != NULL) {
                        int buf = htonl(RESULT);
                        SSL_write(ssl, &buf, sizeof(int));

                        int n;
                        // Lecture des résultats de la commande et envoi via SSL
                        while ((n = fread(buffer, 1, sizeof(buffer), fichier)) > 0) {
                            if (SSL_write(ssl, buffer, n) < 0) {
                                perror("write");
                                break;
                            }
                        }
                        pclose(fichier);
                    } else {
                        perror("popen");
                    }
                }

            }

            else if (message->category == 2) {
                printf("received from server : %s\n", message->payload);
            }
        }
    }

exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);
    close(client_skt);

    printf("Client exiting...\n");

    return EXIT_SUCCESS;
}