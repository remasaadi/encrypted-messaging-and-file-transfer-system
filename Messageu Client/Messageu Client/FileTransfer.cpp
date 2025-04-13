#include "FileTransfer.h"
#include "KeysManagement.h"
#include "Communication.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include "AESWrapper.h"
#include "Client.h"
#include "Base64Wrapper.h"



using namespace std;

FileTransfer::FileTransfer(Communication& comm, KeysManagement& keysManager) : comm(comm), keysManager(keysManager) {}

// פונקציה לשליחת קובץ לשרת
void FileTransfer::sendFile(const string& target_name, const string& file_path) {
    // בדיקה אם שם המשתמש מופיע במפתחות הסימטריים
    std::string target_client_id = findClientIDByUsername(target_name);
    auto it = symmetricKeyStore.find(target_client_id);
    if (it == symmetricKeyStore.end()) {
        cerr << "Error: No symmetric key available for this client." << endl;
        return;
    }

    string symmetricKey = it->second.symmetricKey;

    // פתיחת הקובץ לקריאה בבינארי
    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error: File not found: " << file_path << endl;
        return;
    }

    // קריאת תוכן הקובץ לזיכרון
    file.seekg(0, ios::end);
    streamsize fileSize = file.tellg();
    file.seekg(0, ios::beg);
    vector<char> fileData(fileSize);
    file.read(fileData.data(), fileSize);
    file.close();

    // קריאת Client ID מקובץ me.info
    ClientInfo clientInfo = loadClientInfo();
    string client_id = clientInfo.client_id;
    std::string client_id_bytes = hexStringToBytes(client_id);

    std::string target_client_id_bytes = hexStringToBytes(target_client_id);


    // הצפנת הקובץ באמצעות AES
    string symmetricKeyBinary = Base64Wrapper::decode(symmetricKey);
    AESWrapper aes(reinterpret_cast<const unsigned char*>(symmetricKeyBinary.c_str()), symmetricKeyBinary.size());
    string fileDataString(fileData.begin(), fileData.end());
    string paddedFileData = padMessage(fileDataString);
    string encryptedFile = aes.encrypt(paddedFileData.c_str(), paddedFileData.size());

    // בניית תוכן ההודעה
    vector<char> messagePayload(16 + 1 + 4 + encryptedFile.size());
    memcpy(&messagePayload[0], target_client_id_bytes.c_str(), 16); 
    messagePayload[16] = 4; // Message Type = 4
    uint32_t content_size = encryptedFile.size();
    memcpy(&messagePayload[17], &content_size, sizeof(content_size)); // גודל תוכן ההודעה
    memcpy(&messagePayload[21], encryptedFile.c_str(), encryptedFile.size()); // הצבת תוכן הקובץ המוצפן

    // בניית הבקשה
    vector<char> request(23 + messagePayload.size(), 0);
    memcpy(&request[0], client_id_bytes.c_str(), 16); // Client ID
    request[16] = 2; // Version = 2
    uint16_t code = 603; // Code = 603
    memcpy(&request[17], &code, sizeof(code));
    uint32_t payload_size = messagePayload.size();
    memcpy(&request[19], &payload_size, sizeof(payload_size));
    memcpy(&request[23], messagePayload.data(), messagePayload.size()); // הצבת תוכן ההודעה

    // שליחת הבקשה לשרת
    comm.sendRequest(request);
    vector<char> response = comm.receiveResponse();

    // בדיקת קוד תשובה מהשרת
    if (response.size() < 7) {
        cerr << "Error: Failed to receive response from server." << endl;
        return;
    }

    uint16_t response_code;
    memcpy(&response_code, &response[1], sizeof(response_code));

    if (response_code == 2103) {
        cout << "File sent successfully to client "<<  endl;
    }
    else {
        cout << "Error: Server response indicates failure in sending the file." << endl;
    }
}

// פונקציה לטיפול בקובץ נכנס
void FileTransfer::handleIncomingFile(const string& sender_id, const vector<char>& encryptedContent) {
    // בדיקה אם יש מפתח סימטרי לשולח
    auto it = symmetricKeyStore.find(sender_id);
    if (it == symmetricKeyStore.end()) {
        cerr << "Error: Can't decrypt file. No symmetric key available." << endl;
        return;
    }

    string symmetricKey = it->second.symmetricKey;

    // פענוח הקובץ
    string symmetricKeyBinary = Base64Wrapper::decode(symmetricKey);
    AESWrapper aes(reinterpret_cast<const unsigned char*>(symmetricKeyBinary.c_str()), symmetricKeyBinary.size());
    string encryptedString(encryptedContent.begin(), encryptedContent.end());  // המרה ל-string
    string decryptedPaddedFile = aes.decrypt(encryptedString.c_str(), encryptedString.size());
    string decryptedFile = unpadMessage(decryptedPaddedFile);

    // שמירת הקובץ בתיקיית TEMP
    std::filesystem::path tempPath = std::filesystem::temp_directory_path() / "received_file.dat";
    ofstream outFile(tempPath.string(), ios::binary);
    if (!outFile) {
        cerr << "Error: Unable to save file!" << endl;
        return;
    }
    outFile.write(decryptedFile.c_str(), decryptedFile.size());
    outFile.close();

    // הצגת הנתיב המלא במקום התוכן
    cout << "File received and saved at: " << tempPath.string() << endl;
}

std::string FileTransfer::findClientIDByUsername(const std::string& username) {
    for (const auto& entry : symmetricKeyStore) {
        if (entry.second.username == username) {
            return entry.first;
        }
    }
    return "Not found";
}

// הוספת Padding לפי גודל בלוק
std::string FileTransfer::padMessage(const std::string& message, size_t blockSize) {
    size_t paddingNeeded = blockSize - (message.size() % blockSize);
    return message + std::string(paddingNeeded, static_cast<char>(paddingNeeded));
}


// הסרת Padding לאחר פענוח
std::string FileTransfer::unpadMessage(const std::string& paddedMessage) {
    if (paddedMessage.empty()) return "";
    size_t paddingValue = static_cast<unsigned char>(paddedMessage.back());
    if (paddingValue > paddedMessage.size()) return "";
    return paddedMessage.substr(0, paddedMessage.size() - paddingValue);
}

