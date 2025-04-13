#pragma once

#include <boost/asio.hpp>
#include <vector>
#include <string>

#define SERVER_INFO_FILE "server.info"
#define BUFFER_SIZE 1024

class Communication {
public:
    // קונסטרקטור שמקבל רפרנס לסוקט (לא יוצרים אותו פה)
    Communication(boost::asio::ip::tcp::socket& socket);

    // שליחת בקשה לשרת
    void sendRequest(const std::vector<char>& request);

    // קבלת תשובה מהשרת
    std::vector<char> receiveResponse();

private:
    boost::asio::ip::tcp::socket& socket; // רפרנס לסוקט של Boost Asio
};

// פונקציה לטעינת כתובת השרת מתוך קובץ
std::string loadServerAddress();
