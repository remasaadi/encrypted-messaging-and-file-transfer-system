#include "Communication.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <boost/asio.hpp>

using namespace std;
using boost::asio::ip::tcp;

string loadServerAddress() {
    ifstream file(SERVER_INFO_FILE);
    string address;
    cout << "Trying to open file at: " << SERVER_INFO_FILE << endl;
    cout << "Current working directory: " << filesystem::current_path() << endl;

    if (!file.is_open()) {
        cerr << "Error: Could not open file: " << SERVER_INFO_FILE << endl;
        return "";
    }

    cout << "Debug: Successfully opened file " << SERVER_INFO_FILE << endl;

    if (!getline(file, address)) {
        cerr << "Error: Failed to read from file!" << endl;
        return "";
    }

    file.close();
    address.erase(remove_if(address.begin(), address.end(), ::isspace), address.end());

    if (address.empty()) {
        cerr << "Error: The file is empty or was not read correctly." << endl;
    }

    return address;
}

Communication::Communication(tcp::socket& socket) : socket(socket) {}

void Communication::sendRequest(const vector<char>& request) {
    try {
        boost::asio::write(socket, boost::asio::buffer(request));
    }
    catch (const std::exception& e) {
        cerr << "Send failed: " << e.what() << endl;
    }
}

vector<char> Communication::receiveResponse() {
    vector<char> buffer(BUFFER_SIZE);
    try {
        size_t bytesReceived = socket.read_some(boost::asio::buffer(buffer));
        buffer.resize(bytesReceived);
    }
    catch (const std::exception& e) {
        cerr << "Receive failed: " << e.what() << endl;
    }
    return buffer;
}
