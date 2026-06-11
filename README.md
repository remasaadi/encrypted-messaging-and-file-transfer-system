# Encrypted Messaging and File Transfer System

## Overview

A secure client-server messaging and file transfer system developed using **C++** and **Python**.

The project enables users to exchange messages and transfer files securely through encrypted communication channels. It combines a high-performance C++ client application with a Python-based server, implementing modern cryptographic techniques to ensure confidentiality and secure data exchange.

---

## Features

* Secure client-server architecture
* Real-time messaging
* Secure file transfer
* User authentication
* RSA public-key encryption
* AES symmetric encryption
* Key management and exchange
* Encrypted communication channels
* Modular and scalable design

---

## Technologies Used

### Client Side

* C++
* Visual Studio
* Boost.Asio
* Crypto++

### Server Side

* Python
* Socket Programming

### Security & Cryptography

* RSA Encryption
* AES Encryption
* Base64 Encoding
* Secure Key Exchange

---

## System Architecture

The system consists of two main components:

### Messageu Client

A C++ desktop application responsible for:

* User interaction
* Message encryption and decryption
* Secure file transfer
* Communication with the server

### Messageu Server

A Python server responsible for:

* Managing client connections
* Message routing
* Authentication handling
* Secure communication management

---

## Project Structure

```text
encrypted-messaging-and-file-transfer-system
│
├── Messageu Client
│   ├── Client
│   ├── Crypto Modules
│   ├── Communication Modules
│   └── File Transfer Modules
│
├── Messageu Server
│
├── README.md
└── .gitignore
```

---

## How to Run

### Client

1. Open `Messageu Client.sln` in Visual Studio.
2. Build the solution.
3. Run the client application.

### Server

1. Navigate to the server directory.
2. Install required Python dependencies.
3. Run the server:

```bash
python server.py
```

4. Connect the client to the running server.

---

## Learning Outcomes

This project provided hands-on experience with:

* Client-server architecture
* Network programming
* Secure communication protocols
* Cryptographic algorithms
* Software modularization
* Cross-language system development (C++ and Python)

---

## Author

**Rema Saadi**

Computer Science Student | Open University
