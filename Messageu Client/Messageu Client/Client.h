#pragma once

#include <string>
#include <boost/filesystem.hpp>
#include "Communication.h"

// קובץ שבו נשמרים פרטי הלקוח
#define CLIENT_INFO_FILE "me.info"

// מבנה לאחסון פרטי הלקוח
struct ClientInfo {
    std::string username;
    std::string client_id;
    std::string private_key;
};

// פונקציות לניהול הלקוח
ClientInfo loadClientInfo(); // טעינת מידע הלקוח מהקובץ
void registerClient(Communication& comm); // רישום לקוח באמצעות Communication
void saveClientInfo(const std::string& username, const std::string& clientID, const std::string& privateKey); // שמירת מידע הלקוח
std::string hexify(const std::string& input); // המרת מחרוזת להקסדצימלי
void clearClientInfo(); // ניקוי קובץ me.info
std::string hexStringToBytes(const std::string& hex);
std::string bytesToHex(const std::vector<unsigned char>& bytes);
std::string readClientID();

