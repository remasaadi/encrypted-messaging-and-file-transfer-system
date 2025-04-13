#include "Requests.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstring>
#include "Client.h"
#include <winsock2.h>  // דרוש ל-htons() ו-ntohs() ב-Windows
#pragma comment(lib, "Ws2_32.lib")  // קישור לספריית Winsock

using namespace std;


Requests::Requests(Communication& comm) : comm(comm) {}

void Requests::requestClientsList() {
    vector<char> request(23, 0);
    string clientID = readClientID();
    std::string client_id_bytes = hexStringToBytes(clientID);
    memcpy(&request[0], client_id_bytes.c_str(), 16);
    request[16] = 2; // גרסת הפרוטוקול

    uint16_t requestCode = 601;
    memcpy(&request[17], &requestCode, sizeof(requestCode));

    uint32_t payloadSize = 0;
    memcpy(&request[19], &payloadSize, sizeof(payloadSize));

    // שליחת הבקשה דרך Communication
    comm.sendRequest(request);

    // **?? שלב 1: קריאת ה-Header בלבד (7 בתים ראשונים)**
    vector<char> response_header = comm.receiveResponse();
    if (response_header.size() < 7) {
        cerr << "Error: Failed to receive full header." << endl;
        return;
    }

    // קריאת `payload_size` מתוך ה-Header
    uint32_t payload_size;
    memcpy(&payload_size, &response_header[3], sizeof(payload_size));

    cout << "Payload size: " << payload_size << endl;

    // **?? שלב 2: קריאת שאר הנתונים בלולאה**
    vector<char> response = response_header;  // מתחילים עם מה שקיבלנו עד עכשיו
    while (response.size() < (7 + payload_size)) {
        vector<char> temp = comm.receiveResponse(); // מקבלים עוד חלק מהנתונים
        if (temp.empty()) {
            cerr << "Error: Connection lost while receiving response." << endl;
            return;
        }
        response.insert(response.end(), temp.begin(), temp.end()); // מחברים את החלק החדש
        cout << "Received total: " << response.size() << "/" << (7 + payload_size) << " bytes." << endl;
    }

    cout << "Final response size: " << response.size() << endl;

    // **?? בדיקת שגיאות**
    if (response.size() < 7 || (response.size() >= 7 && (*reinterpret_cast<uint16_t*>(&response[2])) == 9000)) {
        cout << "Server responded with an error." << endl;
        return;
    }

    // **?? פירוק הנתונים מהתשובה**
    uint16_t responseCode;
    memcpy(&responseCode, &response[2], sizeof(responseCode));

    if (payload_size % 271 != 0) {
        cout << "Error: Invalid response format." << endl;
        return;
    }

    cout << "Clients List:" << endl;
    int num_clients = payload_size / 271;

    for (int i = 0; i < num_clients; i++) {
        if (response.size() < (7 + (i * 271) + 271)) {
            cout << "Error: Response too short for client " << i << endl;
            break;
        }

        string client_id(response.begin() + 7 + (i * 271), response.begin() + 7 + (i * 271) + 16);
        string client_name(response.begin() + 7 + (i * 271) + 16, response.begin() + 7 + (i * 271) + 271);
        client_name = client_name.c_str(); // חיתוך עד `NULL`
        cout << "- " << client_name << endl;
    }
}
