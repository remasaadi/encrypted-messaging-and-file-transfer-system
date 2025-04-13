#include "Messages.h"
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include "KeysManagement.h"
#include "Client.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "FileTransfer.h"


using namespace std;

Messages::Messages(Communication& comm, KeysManagement& keysManager) : comm(comm), keysManager(keysManager) {}

void Messages::fetchPendingMessages() {
    //me.info מקובץ Client ID קריאת 
    ClientInfo clientInfo = loadClientInfo();
    string client_id = clientInfo.client_id;
    std::string client_id_bytes = hexStringToBytes(client_id);
    // בניית בקשה הודעות ממתינות
    vector<char> request(23, 0);
    memcpy(&request[0], client_id_bytes.c_str(), 16); // Client ID
    request[16] = 2;
    uint16_t code = 604;
    memcpy(&request[17], &code, sizeof(code));
    uint32_t payload_size = 0;
    memcpy(&request[19], &payload_size, sizeof(payload_size));
    // שליחת הבקשה לשרת
    comm.sendRequest(request);
    vector<char> response = comm.receiveResponse();

    // בדיקת תקינות התשובה
    if (response.size() < 7) {
        cout << "Server responded with an error or invalid response." << endl;
        return;
    }

    // חילוץ הנתונים מהתשובה
    uint8_t version;
    uint16_t response_code;
    uint32_t payload_size_response;

    memcpy(&version, &response[0], sizeof(version));
    memcpy(&response_code, &response[1], sizeof(response_code));
    memcpy(&payload_size_response, &response[3], sizeof(payload_size_response));
    if (response_code != 2104) {
        cout << "Error: Unexpected response code from server." << endl;
        return;
    }

    if (payload_size_response == 0) {
        cout << "No pending messages." << endl;
        return;
    }

    // ניתוח תוכן ההודעות הממתינות
    int offset = 7;
    while (offset < response.size()) {
        //  השולח ID (16 bytes) קריאת
        std::string sender_id_bytes(response.begin() + offset, response.begin() + offset + 16);
        std::string sender_id_hex = hexify(sender_id_bytes);
        offset += 16;

        //  message_id (4 bytes) קריאת
        int message_id;
        memcpy(&message_id, &response[offset], sizeof(int));

        offset += 4;

        //  message_type (1 byte) קריאת
        uint8_t message_type;
        memcpy(&message_type, &response[offset], sizeof(uint8_t));
        offset += 1;

        //  message_size (4 bytes) קריאת
        int message_size;
        memcpy(&message_size, &response[offset], sizeof(int));
        offset += 4;

        // בדיקה אם message_size חוקי
        if (offset + message_size > response.size()) {
            break;
        }

        // קריאת תוכן ההודעה
        string message_content(response.begin() + offset, response.begin() + offset + message_size);
        offset += message_size; //להודעה הבאה offset עדכון ה


        std::string sender_username = "Not found";
        for (const auto& entry : publicKeyStore) {
            if (entry.second.clientID == sender_id_hex) {
                sender_username = entry.first;
                break;
            }
        }
        cout << "From: " << sender_username << endl;
        switch (message_type) {
        case 1:
            cout << "Content: Request for symmetric key" << endl;
            break;
        case 2:
            cout << "Content: Symmetric key received" << endl;
            // שמירת המפתח הסימטרי במבנה הנתונים

            if (sender_username != "Not found") {
                ClientInfo clientInfo = loadClientInfo();
                string privateKeyBase64;
                for (char c : clientInfo.private_key) {
                    if (!isspace(c)) { // הסרת רווחים מיותרים
                        privateKeyBase64 += c;
                    }
                }
                string privateKeyBinary = Base64Wrapper::decode(privateKeyBase64);
                RSAPrivateWrapper rsaClient(privateKeyBinary);
                std::string decryptedSymmetricKey = rsaClient.decrypt(message_content);
                symmetricKeyStore[sender_id_hex] = { sender_username, sender_id_hex, decryptedSymmetricKey };
                cout << "Stored symmetric key for client: " << sender_username << endl;
            }
            else {
                cout << "Warning: Received symmetric key but sender is not in publicKeyStore." << endl;
            }

            break;
        case 3:
            if (symmetricKeyStore.find(sender_id_hex) != symmetricKeyStore.end()) {
                auto it = symmetricKeyStore.find(sender_id_hex);
                std::string SymmetricKeyBase64 = it->second.symmetricKey;
                std::string BinarySymmetricKey = Base64Wrapper::decode(SymmetricKeyBase64);
                std::string decodedMessageContent = Base64Wrapper::decode(message_content);
                AESWrapper aes(reinterpret_cast<const unsigned char*>(BinarySymmetricKey.c_str()), BinarySymmetricKey.size());
                string decryptedMessage = aes.decrypt(decodedMessageContent.c_str(), decodedMessageContent.size());
                string finalMessage = unpadMessage(decryptedMessage);
                cout << "contant: " << finalMessage << endl;
            }
            else {
                cout << "Content: Cannot encrypt message (missing symmetric key)" << endl;
            }
            break;
        case 4: {
            cout << "Content: Incoming file received" << endl;

            // העברת תוכן מוצפן לוקטור
            vector<char> encryptedFileContent(message_content.begin(), message_content.end());

            // קריאה לפונקציה שמטפלת בקובץ
            FileTransfer fileTransfer(comm, keysManager);
            fileTransfer.handleIncomingFile(sender_id_hex, encryptedFileContent);
            break;
        }
        default:
            cout << "Unknown message type." << endl;
            break;
        }
        cout << "-----<EOM>-----\n" << endl;

    }
}

void Messages::sendTextMessage() {
    string target_name, message;

    cout << "Enter target client name: ";
    cin >> target_name;
    cout << "Enter message: ";
    cin.ignore();
    getline(cin, message);

    std::string target_client_id = findClientIDByUsername(target_name);
    if (target_client_id == "Not found") {
        cout << "Error: client Not Found Or no symmetric key ." << endl;
        return;
    }

    std::string target_client_id_bytes = hexStringToBytes(target_client_id);
    auto it = symmetricKeyStore.find(target_client_id);
    if (it == symmetricKeyStore.end()) {
        cout << "Error: No symmetric key found for client ID: " << target_client_id << endl;
        return;
    }

    ClientInfo clientInfo = loadClientInfo();
    string privateKeyBase64;
    for (char c : clientInfo.private_key) {
        if (!isspace(c)) { // מסיר רווחים מיותרים
            privateKeyBase64 += c;
        }
    }

    //string privateKeyBinary = Base64Wrapper::decode(privateKeyBase64);
    //RSAPrivateWrapper rsaClient(privateKeyBinary);
    std::string SymmetricKey = it->second.symmetricKey;
    //std::string decryptedSymmetricKey = rsaClient.decrypt(encryptedSymmetricKey);
    std::string BinarySymmetricKey = Base64Wrapper::decode(SymmetricKey);

    //if (decryptedSymmetricKey.empty()) {
      //  cout << "Error: Failed to decrypt symmetric key." << endl;
     //   return;
   // }

    std::string finalSymmetricKey = BinarySymmetricKey;
    if (finalSymmetricKey.size() != 16) {
        cout << "Error: Invalid symmetric key size! Expected 16 bytes, got " << finalSymmetricKey.size() << endl;
        return;
    }

    AESWrapper aes(reinterpret_cast<const unsigned char*>(finalSymmetricKey.c_str()), finalSymmetricKey.size());

    //לפני הצפנה Padding הוספת Padding 
    string paddedMessage = padMessage(message, 16);
    string encryptedMessage = aes.encrypt(paddedMessage.c_str(), paddedMessage.size());
    string encryptedBase64 = Base64Wrapper::encode(encryptedMessage);

    vector<char> messagePayload(16 + 1 + 4 + encryptedBase64.size());
    memcpy(&messagePayload[0], target_client_id_bytes.c_str(), 16);
    messagePayload[16] = 3;
    uint32_t content_size = encryptedBase64.size();
    memcpy(&messagePayload[17], &content_size, sizeof(content_size));
    memcpy(&messagePayload[21], encryptedBase64.c_str(), encryptedBase64.size());

    vector<char> request(23 + messagePayload.size(), 0);
    std::string client_id_bytes = hexStringToBytes(clientInfo.client_id);
    memcpy(&request[0], client_id_bytes.c_str(), 16);
    request[16] = 2;
    uint16_t code = 603;
    memcpy(&request[17], &code, sizeof(code));
    uint32_t payload_size = messagePayload.size();
    memcpy(&request[19], &payload_size, sizeof(payload_size));
    memcpy(&request[23], messagePayload.data(), messagePayload.size());

    comm.sendRequest(request);
    vector<char> response = comm.receiveResponse();

    if (response.size() < 7) {
        cout << "Error: Failed to receive response from server." << endl;
        return;
    }

    uint16_t response_code;
    memcpy(&response_code, &response[1], sizeof(response_code));

    if (response_code == 2103) {
        cout << "Text message sent successfully." << endl;
    }
    else {
        cout << "Error: Server response indicates failure in sending the message." << endl;
    }
}


//  Padding הוספת
std::string Messages::padMessage(const std::string& message, size_t blockSize) {
    size_t paddingNeeded = blockSize - (message.size() % blockSize);
    return message + std::string(paddingNeeded, static_cast<char>(paddingNeeded));
}

//  Padding הסרת
std::string Messages::unpadMessage(const std::string& paddedMessage) {
    if (paddedMessage.empty()) return "";
    size_t paddingValue = static_cast<size_t>(paddedMessage.back());
    if (paddingValue > paddedMessage.size()) return "";  // בדיקה אם הפדינג תקין
    return paddedMessage.substr(0, paddedMessage.size() - paddingValue);
}
// פונקציה למציאת ID 
std::string Messages::findClientIDByUsername(const std::string& username) {
    for (const auto& entry : symmetricKeyStore) {
        if (entry.second.username == username) {
            return entry.first;
        }
    }
    return "Not found";
}
