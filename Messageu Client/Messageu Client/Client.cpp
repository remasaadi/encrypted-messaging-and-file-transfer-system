#include "Client.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include "CryptoUtils.h"
#include "Communication.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"

#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

using namespace std;
using namespace boost::filesystem;

ClientInfo loadClientInfo() {
    ifstream file(CLIENT_INFO_FILE);
    ClientInfo info;
    if (!file.is_open()) {
        cerr << "Error: Unable to open " << CLIENT_INFO_FILE << endl;
        return info;
    }

    // קריאה של שם המשתמש והשורה השנייה (Client ID)
    getline(file, info.username);
    getline(file, info.client_id);

    // קריאת כל המפתח הפרטי מהשורה השלישית והלאה
    string line;
    info.private_key.clear();
    while (getline(file, line)) {
        info.private_key += line + "\n";  // שומרים כל שורה עם מעבר שורה
    }

    file.close();
    return info;
}

string readClientID() {
    ifstream file(CLIENT_INFO_FILE);
    if (!file) {
        cerr << "Error: Unable to open " << CLIENT_INFO_FILE << endl;
        return string(16, '\0');  // החזרת מחרוזת ריקה בגודל 16 בתים
    }

    string line, clientID;

    // דילוג על השורה הראשונה (שם המשתמש)
    getline(file, line);

    // קריאת השורה השנייה (מזהה הלקוח ב-hex)
    if (getline(file, clientID)) {
        if (clientID.size() != 32) {  // 16 בתים ב-hex -> 32 תווים
            cerr << "Error: Invalid clientID format in me.info" << endl;
            return string(16, '\0');
        }

        return clientID;
    }

    cerr << "Error: Missing clientID in me.info" << endl;
    return string(16, '\0');
}

void registerClient(Communication& comm) {
    ifstream checkFile(CLIENT_INFO_FILE, ios::ate);
    if (checkFile.good() && checkFile.tellg() > 0) {
        cout << "Error: Already registered!" << endl;
        return;
    }
    checkFile.close();

    string username;
    cout << "Enter your username: ";
    cin.ignore();
    getline(cin, username);

    if (username.length() > 254) {
        cout << "Error: Username too long!" << endl;
        return;
    }

    RSAPrivateWrapper rsa;
    string privateKey = Base64Wrapper::encode(rsa.getPrivateKey());
    string publicKey = rsa.getPublicKey();

    vector<char> request(23 + 255 + 160, 0);
    string clientID = string(16, '\0');
    memcpy(&request[0], clientID.c_str(), 16);

    request[16] = 2;

    uint16_t requestCode = 600;  // ללא המרה ל-Big-Endian
    memcpy(&request[17], &requestCode, sizeof(requestCode));

    uint32_t payloadSize = 255 + 160;  // ללא המרה ל-Big-Endian
    memcpy(&request[19], &payloadSize, sizeof(payloadSize));

    memcpy(&request[23], username.c_str(), username.size());
    request[23 + username.size()] = '\0';

    memcpy(&request[23 + 255], publicKey.c_str(), min(publicKey.size(), (size_t)160));

    try {
        comm.sendRequest(request);
        vector<char> response = comm.receiveResponse();

        if (response.size() < 23) {
            cout << "Error: Invalid server response!" << endl;
            return;
        }

        uint8_t version;
        uint16_t responseCode;
        uint32_t payloadSize;
        char clientID[16];

        memcpy(&version, &response[0], sizeof(version));
        memcpy(&responseCode, &response[1], sizeof(responseCode));
        memcpy(&payloadSize, &response[3], sizeof(payloadSize));
        memcpy(clientID, &response[7], 16);


        if (responseCode == 2100) {
            string clientID(response.begin() + 7, response.begin() + 7 + 16);
            saveClientInfo(username, clientID, privateKey);
            cout << "Registration successful!" << endl;
        }
        else {
            cout << "Error: Username already exists!" << endl;
        }
    }
    catch (const std::exception& e) {
        cerr << "Connection error: " << e.what() << endl;
    }
}

void saveClientInfo(const string& username, const string& clientID, const string& privateKey) {
    try {
        path filePath(CLIENT_INFO_FILE);
        ofstream file(filePath.string());

        if (!file) {
            cout << "Error: Unable to save client info!" << endl;
            return;
        }
        file << username << endl;
        file << hexify(clientID) << endl;
        file << privateKey << endl;
        file.close();
    }
    catch (const std::exception& e) {
        cerr << "File error: " << e.what() << endl;
    }
}

std::string hexify(const std::string& input) {
    stringstream ss;
    for (unsigned char c : input) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

void clearClientInfo() {
    ofstream file("me.info", ios::trunc);
    if (file) {
        cout << "Client info cleared successfully." << endl;
    }
    else {
        cerr << "Error: Unable to clear client info file." << endl;
    }
}

std::string hexStringToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }

    std::string bytes;
    bytes.reserve(hex.length() / 2); // הקצאת מקום לשיפור ביצועים

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::ostringstream hexStream;
    for (unsigned char byte : bytes) {
        hexStream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte);
    }
    return hexStream.str();
}
