//
// Created by Florian Touraine on 07/05/2025.
//

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif
