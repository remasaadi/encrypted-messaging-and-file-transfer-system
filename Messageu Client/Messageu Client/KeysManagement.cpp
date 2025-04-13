#include "KeysManagement.h"
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "Requests.h"
#include "AESWrapper.h"
#include "Client.h"
#include <fstream>
#include <cstring>
#include <winsock2.h>  // לשימוש בפונקציות רשת
#pragma comment(lib, "Ws2_32.lib")

using namespace std;
KeysManagement::KeysManagement(Communication& comm) : comm(comm) {}

std::unordered_map<std::string, PublicKeyEntry> publicKeyStore;
std::unordered_map<std::string, SymmetricKeyEntry> symmetricKeyStore;

void KeysManagement::requestPublicKey(const string& target_name) {
    vector<char> request(23 + target_name.size(), 0);
    string clientID = readClientID(); // קריאת מזהה הלקוח
    std::string client_id_bytes = hexStringToBytes(clientID);

    memcpy(&request[0], client_id_bytes.c_str(), 16); // הצבת Client ID
    request[16] = 2; // גרסת הפרוטוקול

    uint16_t requestCode = 602; // קוד הבקשה
    memcpy(&request[17], &requestCode, sizeof(requestCode));

    uint32_t payloadSize = 16; // גודל ה-payload
    memcpy(&request[19], &payloadSize, sizeof(payloadSize));

    memcpy(&request[23], target_name.c_str(), target_name.size()); // שם המשתמש המבוקש

    comm.sendRequest(request);
    vector<char> response = comm.receiveResponse();

    if (response.size() < 7) {
        cout << "Error: Failed to receive public key response." << endl;
        return;
    }

    uint8_t version = static_cast<uint8_t>(response[0]);
    uint16_t responseCode;
    uint32_t payloadSizeResponse;

    memcpy(&responseCode, &response[1], sizeof(responseCode));
    // בדיקת שגיאה בקוד תשובה
    if (responseCode == 9000) {
        cout << "Error: Failed to retrieve public key – client may not exist." << endl;
        return;
    }
    memcpy(&payloadSizeResponse, &response[3], sizeof(payloadSizeResponse));
    // בדיקה אם התשובה מכילה נתונים מעבר לכותרת
    if (response.size() < 7 + payloadSizeResponse) {
        cout << "Error: Incomplete response received." << endl;
        return;
    }

    // יצירת אינדקס לקריאת נתונים
    size_t offset = 7;
    std::string clientIDBytes(response.begin() + offset, response.begin() + offset + 16);
    offset += 16;

    std::string target_client_id_hex = hexify(clientIDBytes);
    std::string publicKeyStr;
    // **קריאת המפתח הציבורי**
    for (size_t i = 0; i < 160; i++) {
        publicKeyStr += response[offset + i];
    }
    offset += 160;

    string publicKeyBase64 = Base64Wrapper::encode(publicKeyStr);

    // **שמירת המידע במבנה הנתונים**
    publicKeyStore[target_name] = { target_name, target_client_id_hex, publicKeyBase64 };
    cout << " Public key stored successfully." << endl; 
}

// פונקציה לשליחת בקשת מפתח סימטרי
void KeysManagement::requestSymmetricKey(const string& target_name) {

    // בדיקה אם שם המשתמש מופיע במפתחות הציבוריים
    string clientID = "";
    for (const auto& entry : publicKeyStore) {
        if (entry.second.username == target_name) {
            clientID = entry.second.clientID;
            break;
        }
    }

    if (clientID.empty() || publicKeyStore.find(target_name) == publicKeyStore.end()) {
        cout << "Error: No public key found for user: " << target_name << endl;
        return;
    }

    string target_client_id = publicKeyStore[target_name].clientID;

    // בדיקה אם כבר יש מפתח סימטרי מול לקוח זה
    if (symmetricKeyStore.find(target_name) != symmetricKeyStore.end()) {
        cout << "Symmetric key already exists for client: " << target_name << endl;
        return;
    }

    std::string target_client_id_bytes = hexStringToBytes(target_client_id);
    // קריאת Client ID מקובץ me.info
    ClientInfo clientInfo = loadClientInfo();
    string client_id = clientInfo.client_id;
    std::string client_id_bytes = hexStringToBytes(client_id);

    // יצירת הודעת בקשה למפתח סימטרי 
    vector<char> plaintextRequest(21, 0);
    memcpy(&plaintextRequest[0], target_client_id_bytes.c_str(), 16); // Client ID של היעד
    plaintextRequest[16] = 1; // Message Type = 1
    uint32_t message_content_size = 0;
    memcpy(&plaintextRequest[17], &message_content_size, sizeof(message_content_size)); // Content Size = 0

    // בניית הבקשה
    vector<char> request(23 + plaintextRequest.size(), 0);
    memcpy(&request[0], client_id_bytes.c_str(), 16);
    request[16] = 2; // גרסת הפרוטוקול
    uint16_t code = 603; // קוד הבקשה
    memcpy(&request[17], &code, sizeof(code));
    uint32_t content_size = plaintextRequest.size();
    memcpy(&request[19], &content_size, sizeof(content_size));
    memcpy(&request[23], plaintextRequest.data(), plaintextRequest.size()); // הצבת ההודעה ללא הצפנה

    // שליחת הבקשה לשרת
    comm.sendRequest(request);
    vector<char> response = comm.receiveResponse();

    if (response.size() < 23) {
        cout << "Error: Invalid response from server." << endl;
        return;
    }

    uint16_t response_code;
    memcpy(&response_code, &response[1], sizeof(response_code));

    if (response_code == 2103)
        cout << "Request for symmetric key sent successfully." << endl;
    else
        cout << "Error: Failed to send request for symmetric key." << endl;
}


// פונקציה לשליחת מפתח סימטרי
void KeysManagement::sendSymmetricKey(const string& target_name) {
    // בדיקה אם שם המשתמש מופיע במפתחות הציבוריים
    if (publicKeyStore.find(target_name) == publicKeyStore.end()) {
        cout << "Error: No public key found for user: " << target_name << endl;
        return;
    }

    string target_client_id_hex = publicKeyStore[target_name].clientID;
    std::string target_client_id_bytes = hexStringToBytes(target_client_id_hex);
    string public_key_base64 = publicKeyStore[target_name].publicKey;

    // המרת המפתח הציבורי מפורמט Base64 לבינארי
    string public_key = Base64Wrapper::decode(public_key_base64);
    if (public_key.empty()) {
        cout << "Error: Failed to decode public key." << endl;
        return;
    }
    // יצירת מפתח סימטרי באמצעות GenerateKey
    unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
    AESWrapper::GenerateKey(key, AESWrapper::DEFAULT_KEYLENGTH);
    string symmetric_key(reinterpret_cast<char*>(key), AESWrapper::DEFAULT_KEYLENGTH);

    // קידוד המפתח הסימטרי ב-Base64
    string symmetric_key_base64 = Base64Wrapper::encode(symmetric_key);

    // שמירת המפתח הסימטרי המקודד במבנה הנתונים
    symmetricKeyStore[target_client_id_hex] = { target_name,target_client_id_hex, symmetric_key_base64};

    // הצפנת המפתח הסימטרי באמצעות המפתח הציבורי של היעד
    RSAPublicWrapper rsa(public_key);
    string encrypted_symmetric_key = rsa.encrypt(symmetric_key_base64);


    // קריאת Client ID מקובץ me.info
    ClientInfo clientInfo = loadClientInfo();
    string client_id = clientInfo.client_id;
    std::string client_id_bytes = hexStringToBytes(client_id);

    // בניית תוכן ההודעה
    vector<char> messagePayload(16 + 1 + 4 + encrypted_symmetric_key.size());
    memcpy(&messagePayload[0], target_client_id_bytes.c_str(), 16); // Client ID של היעד
    messagePayload[16] = 2; // Message Type = 2
    uint32_t content_size = encrypted_symmetric_key.size();
    memcpy(&messagePayload[17], &content_size, sizeof(content_size)); // גודל תוכן ההודעה
    memcpy(&messagePayload[21], encrypted_symmetric_key.c_str(), encrypted_symmetric_key.size()); // הצבת המפתח הסימטרי המוצפן

    // בניית הבקשה
    vector<char> request(23 + messagePayload.size(), 0);
    memcpy(&request[0], client_id_bytes.c_str(), 16); // Client ID
    request[16] = 2; // גרסת הפרוטוקול
    uint16_t code = 603; // קוד הבקשה
    memcpy(&request[17], &code, sizeof(code));
    uint32_t payload_size = messagePayload.size();
    memcpy(&request[19], &payload_size, sizeof(payload_size));
    memcpy(&request[23], messagePayload.data(), messagePayload.size()); // הצבת תוכן ההודעה

   
    // שליחת הבקשה לשרת
    comm.sendRequest(request);

    // קבלת תשובה מהשרת
    vector<char> response = comm.receiveResponse();
    if (response.size() < 7) {
        cout << "Error: Invalid response from server." << endl;
        return;
    }

    uint16_t response_code;
    memcpy(&response_code, &response[1], sizeof(response_code));

    if (response_code == 2103) {
        cout << "Symmetric key sent successfully." << endl;
    }
    else {
        cout << "Error: Failed to send symmetric key." << endl;
    }
}
