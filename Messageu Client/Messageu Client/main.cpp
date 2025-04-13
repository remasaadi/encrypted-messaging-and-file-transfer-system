#include <iostream>
#include <boost/asio.hpp>
#include <algorithm>
#include <cstdlib>
#include "Client.h"
#include "Communication.h"
#include "FileTransfer.h"
#include "KeysManagement.h"
#include "Messages.h"
#include "Requests.h"

using namespace std;
using boost::asio::ip::tcp;

//void registerCleanup() {
    //atexit(clearClientInfo);  // פונקציה זו תופעל אוטומטית כשמתבצעת יציאה מהתוכנית
//}
int main() {
    boost::asio::io_context ioContext;

    // יצירת אובייקטים לתקשורת וניהול מפתחות
    tcp::socket socket(ioContext);
    Communication comm(socket);
    KeysManagement keysManager(comm);
    Requests requests(comm);
    FileTransfer fileTransfer(comm, keysManager);
    Messages messages(comm, keysManager);

    // טעינת כתובת השרת
    string serverAddress = loadServerAddress();
    cout << "Server address: " << serverAddress << endl;

    size_t colonPos = serverAddress.find(":");
    if (colonPos == string::npos) {
        cerr << "Error: Server address format is incorrect. Expected format: IP:PORT" << endl;
        return 1;
    }

    string ip = serverAddress.substr(0, colonPos);
    string portStr = serverAddress.substr(colonPos + 1);

    if (portStr.empty() || !all_of(portStr.begin(), portStr.end(), ::isdigit)) {
        cerr << "Error: Invalid port number in server address" << endl;
        return 1;
    }

    int port = stoi(portStr);

    try {
        tcp::resolver resolver(ioContext);
        tcp::resolver::results_type endpoints = resolver.resolve(ip, to_string(port));
        boost::asio::connect(socket, endpoints);
        cout << "Connected to server." << endl;

        while (true) {
            cout << "MessageU client at your service." << endl;
            cout << "110) Register" << endl;
            cout << "120) Request for clients list" << endl;
            cout << "130) Request for public key" << endl;
            cout << "140) Request for waiting messages" << endl;
            cout << "150) Send a text message" << endl;
            cout << "151) Send a request for symmetric key" << endl;
            cout << "152) Send your symmetric key" << endl;
            cout << "153) Send a file" << endl;
            cout << "0) Exit client" << endl;
            cout << "? ";

            int choice;
            cin >> choice;

            if (choice == 0) {
                //clearClientInfo(); // ניקוי קובץ `me.info`
                break;
            }


            string target_name, target_pubkey, sym_key, file_path;

            switch (choice) {
            case 110:
                registerClient(comm);
                break;
            case 120:
                cout << "Requesting clients list..." << endl;
                requests.requestClientsList();
                break;
            case 130:
                cout << "Enter target client name: ";
                cin >> target_name;
                keysManager.requestPublicKey(target_name);
                break;
            case 140:
                cout << "Requesting waiting messages..." << endl;
                messages.fetchPendingMessages();
                break;
            case 150:
                cout << "Sending text message..." << endl;
                messages.sendTextMessage();
                break;
            case 151:
                cout << "Enter target client name: ";
                cin >> target_name;
                keysManager.requestSymmetricKey(target_name);
                break;
            case 152:
                cout << "Enter target client name: ";
                cin >> target_name;
                keysManager.sendSymmetricKey(target_name);
                break;
            case 153:
                cout << "Enter target client name: ";
                cin >> target_name;
                cout << "Enter file path: ";
                cin >> file_path;
                fileTransfer.sendFile(target_name, file_path);
                break;
            default:
                cout << "Invalid option." << endl;
            }
        }

        socket.close();
    }
    catch (const std::exception& e) {
        cerr << "Connection failed: " << e.what() << endl;
        return 1;
    }

    return 0;
}
