# Orchestrateur de Scanners de Vulnérabilités

## Description du projet

Ce projet consiste en la conception et l’implémentation d’un orchestrateur permettant de contrôler à distance plusieurs scanners de vulnérabilités, à savoir :

* **Nmap**
* **OWASP ZAP**
* **Nikto**

L’objectif est d’exécuter des analyses de sécurité sur un ou plusieurs hôtes cibles, de collecter et centraliser les résultats afin de fournir une vue synthétique des vulnérabilités détectées.

### Fonctionnalités

* **Orchestration des scanners** : envoyer des commandes aux scanners distants, configurer les paramètres de scan (cibles, types de tests, options spécifiques).
* **Agent distant** : exécuter les scans sur différentes machines, transmettre les résultats à l’orchestrateur.
* **Communication sécurisée** : chiffrement des échanges entre orchestrateur et agents pour garantir confidentialité et intégrité.
* **Agrégation des résultats** : centralisation et synthèse des vulnérabilités détectées.

### Important

* **Utilisation uniquement dans un environnement contrôlé** (ex : docker, machine virtuelle VirtualBox/VMware, cyber-range dédié).

### Références

* [Nmap](https://nmap.org/)
* [Nikto](https://cirt.net/nikto2)
* [OWASP ZAP](https://www.zaproxy.org/)

---

## Compilation et exécution

### Prérequis

* Clang
* OpenSSL (installé, par exemple via Homebrew sur macOS)
* Make
* Nmap
* OWASP ZAP
* Nikto

### Structure des répertoires

* `src/` : code source
* `ssl/` : certificats et clés SSL
* `build/` : fichiers compilés
* `includes/` : headers

---

### Variables Makefile

```makefile
CC = clang
CFLAGS = -I/opt/homebrew/opt/openssl/include -Iinclude -Wall -Wextra -pthread -fsanitize=address -g
LDFLAGS = -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

SRC_DIR = src
SSL_DIR = ssl
BUILD_DIR = build
INCLUDE_DIR = includes

SERVER_SRC = $(SRC_DIR)/serveur.c $(SRC_DIR)/common.c
CLIENT_SRC = $(SRC_DIR)/client.c $(SRC_DIR)/common.c
SERVER_BIN = $(BUILD_DIR)/serveur
CLIENT_BIN = $(BUILD_DIR)/client

SERVER_IP = 127.0.0.1
SERVER_PORT = 4433
```

---

### Commandes Make

* **Compiler tout** (serveur + client) et créer dossier `build` :

  ```bash
  make all
  ```

* **Nettoyer** les fichiers compilés :

  ```bash
  make clean
  ```

* **Lancer le serveur** sur le port 4433 (par défaut) :

  ```bash
  make run-server
  ```

* **Lancer le client** pour se connecter au serveur sur `127.0.0.1:4433` :

  ```bash
  make run-client
  ```

* **Lancer le client** en spécifiant IP et port via variables d’environnement (exemple) :

  ```bash
  make run-client-ip IP=192.168.1.10 PORT=4433
  ```

---

## Utilisation

Le serveur agit comme orchestrateur central et attend des commandes. Le client est un agent distant qui exécute les scans sur demande.

La communication entre serveur et client est sécurisée via TLS (OpenSSL), utilisant les certificats dans le dossier `ssl/`.

---

## Avertissement

**Ne jamais utiliser ce projet sur un réseau réel.** Toujours exécuter dans un environnement virtuel sécurisé pour éviter toute atteinte non souhaitée à des systèmes externes.

---

""
