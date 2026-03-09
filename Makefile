# =========================
# Compiler et options
# =========================
CC = /usr/bin/clang
SDKROOT := $(shell xcrun --show-sdk-path)
CFLAGS = -I/opt/homebrew/opt/openssl/include -Iinclude -Wall -Wextra -pthread -fsanitize=address -g -isysroot $(SDKROOT)
LDFLAGS = -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

# =========================
# Répertoires
# =========================
SRC_DIR = src
SSL_DIR = ssl
BUILD_DIR = build
INCLUDE_DIR = includes

# =========================
# Fichiers source et binaires
# =========================
SERVER_SRC = $(SRC_DIR)/serveur.c $(SRC_DIR)/common.c
CLIENT_SRC = $(SRC_DIR)/client.c $(SRC_DIR)/common.c
SERVER_BIN = $(BUILD_DIR)/serveur
CLIENT_BIN = $(BUILD_DIR)/client

# =========================
# IP et port par défaut
# =========================
SERVER_IP = 127.0.0.1
SERVER_PORT = 4433

# =========================
# Cibles
# =========================
all: build_dirs $(SERVER_BIN) $(CLIENT_BIN)

build_dirs:
	@mkdir -p $(BUILD_DIR)

$(SERVER_BIN): $(SERVER_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# =========================
# Lancer le serveur
# =========================
run-server: $(SERVER_BIN)
	@echo "Lancement du serveur sur le port $(SERVER_PORT)"
	./$(SERVER_BIN) $(SSL_DIR)/serveur-cert.pem $(SSL_DIR)/serveur-key.pem $(SSL_DIR)/ca-cert.pem $(SERVER_PORT)

# =========================
# Lancer le client
# =========================
run-client: $(CLIENT_BIN)
	@echo "Lancement du client sur $(SERVER_IP):$(SERVER_PORT)"
	./$(CLIENT_BIN) $(SSL_DIR)/client-cert.pem $(SSL_DIR)/client-key.pem $(SSL_DIR)/ca-cert.pem $(SERVER_IP) $(SERVER_PORT)

run-client-ip: $(CLIENT_BIN)
	@echo "Lancement du client sur $(IP):$(PORT)"
	./$(CLIENT_BIN) $(SSL_DIR)/client-cert.pem $(SSL_DIR)/client-key.pem $(SSL_DIR)/ca-cert.pem $(IP) $(PORT)

# =========================
# Nettoyer le build
# =========================
clean:
	rm -rf $(BUILD_DIR)/*

# =========================
# Phony targets
# =========================
.PHONY: all build_dirs run-server run-client run-client-ip clean
