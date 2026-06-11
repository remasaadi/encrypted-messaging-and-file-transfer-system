# Encrypted Messaging and File Transfer System

## Overview

A secure client-server messaging and file transfer system developed using **C++** and **Python**.

The project enables secure communication between users through encrypted messaging and file transfer mechanisms. It combines a high-performance C++ client application with a Python-based server, implementing modern cryptographic techniques to ensure confidentiality, integrity, and secure data exchange.

---

## Features

* Secure client-server architecture
* Real-time messaging
* Secure file transfer
* User authentication
* RSA public-key encryption
* AES symmetric encryption
* Secure key management and exchange
* Encrypted communication channels
* SQLite database integration
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
* SQLite

### Security & Cryptography

* RSA Encryption
* AES Encryption
* Base64 Encoding
* Secure Key Exchange

### Software Engineering Concepts

* Client-Server Architecture
* Modular Design
* Multi-threading
* Network Programming
* Secure File Transfer Protocols

---

## System Architecture

The system consists of two main components:

### Messageu Client (C++)

Responsible for:

* User interaction
* Message encryption and decryption
* Secure file transfer
* Communication with the server
* Cryptographic key handling

### Messageu Server (Python)

Responsible for:

* Managing client connections
* Message routing
* User authentication
* Database management
* Secure communication handling

---

## Project Structure

### Client Modules

* **Client** – client-side operations
* **Communication** – network communication layer
* **FileTransfer** – secure file transfer functionality
* **Messages** – message processing and handling
* **Requests** – request management
* **KeysManagement** – cryptographic key management
* **AESWrapper** – AES encryption implementation
* **RSAWrapper** – RSA encryption implementation
* **Base64Wrapper** – Base64 encoding utilities
* **CryptoUtils** – cryptographic helper functions

### Server Components

* **Messageu Server.py** – main server implementation
* **SQLite Database** – persistent data storage
* **Client Connection Management**
* **Authentication Handling**

---

## Database

The server uses an SQLite database (`defensive.db`) to manage application data and support secure communication and user-related operations.

SQLite was selected because it is lightweight, portable, and easy to integrate into client-server applications.

---

## Technical Challenges

* Designing a secure client-server architecture
* Implementing hybrid encryption using RSA and AES
* Managing cryptographic keys securely
* Implementing encrypted file transfer
* Developing communication protocols between C++ and Python components
* Handling multiple client connections concurrently
* Integrating SQLite database storage
* Building a modular cryptographic framework

---

## How to Run

### Server

1. Navigate to the `Messageu Server` directory.
2. Run the server:

```bash
python "Messageu Server.py"
```

3. The server will initialize and listen for incoming client connections.

### Client

1. Open `Messageu Client.sln` in Visual Studio.
2. Build the solution.
3. Run the client application.
4. Connect to the running server.

---

## Learning Outcomes

This project provided hands-on experience with:

* Cryptography and secure communication
* RSA and AES encryption algorithms
* Socket programming
* Network programming
* Client-server architecture
* Cross-language development (C++ and Python)
* Database integration using SQLite
* Modular software design
* Secure file transfer systems

---

## Author

**Rema Saadi**

Computer Science Student | Open University

📧 [saadi.rema@gmail.com](mailto:saadi.rema@gmail.com)

🔗 linkedin.com/in/rema-saadi
