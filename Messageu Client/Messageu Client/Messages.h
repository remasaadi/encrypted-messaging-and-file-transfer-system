#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include "Communication.h"  // שימוש במחלקת התקשורת עם Boost
#include "AESWrapper.h"     // הצפנת AES
#include "Requests.h"       // שליחת בקשות
#include "KeysManagement.h" // ניהול מפתחות

class Messages {
private:
    Communication& comm;
    KeysManagement& keysManager; // הוספת הפניה לניהול מפתחות

    // הוספת פונקציות לטיפול ב-Padding
    std::string padMessage(const std::string& message, size_t blockSize = 16);
    std::string unpadMessage(const std::string& paddedMessage);
    std::string findClientIDByUsername(const std::string& username);

public:
    Messages(Communication& comm, KeysManagement& keysManager);
    void fetchPendingMessages();
    void sendTextMessage();
};
