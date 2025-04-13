#ifndef KEYS_MANAGEMENT_H
#define KEYS_MANAGEMENT_H

#include "Communication.h"
#include <unordered_map>
#include <string>

using namespace std;

// מבנה נתונים לשמירת Client ID, שם משתמש ומפתח ציבורי
struct PublicKeyEntry {
    std::string username;
    std::string clientID;
    std::string publicKey;
};

// מבנה נתונים לשמירת מפתח סימטרי
struct SymmetricKeyEntry {
    std::string username;
    std::string clientID;
    std::string symmetricKey;
};

// הצהרה על המשתנים כ- extern כדי למנוע שגיאות קישור
extern std::unordered_map<std::string, PublicKeyEntry> publicKeyStore;
extern std::unordered_map<std::string, SymmetricKeyEntry> symmetricKeyStore;

class KeysManagement {
private:
    Communication& comm;

public:
    KeysManagement(Communication& comm);

    void requestPublicKey(const string& client_id);
    void requestSymmetricKey(const string& target_name);
    void sendSymmetricKey(const string& target_name);
};

#endif // KEYS_MANAGEMENT_H
