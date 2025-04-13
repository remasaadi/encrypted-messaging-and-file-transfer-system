#include "CryptoUtils.h"
#include <vector>
#include <stdexcept>  // לשגיאות חריגה

std::string encryptAES(const std::string& message, const std::string& key) {
    // בדיקת גודל המפתח (AES תומך רק ב-16, 24, 32 בתים)
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::invalid_argument("Invalid AES key size. Must be 16, 24, or 32 bytes.");
    }

    // המרת מחרוזת למערך `unsigned char`
    std::vector<unsigned char> keyBytes(key.begin(), key.end());

    // יצירת מופע הצפנה
    AESWrapper aes(keyBytes.data(), static_cast<unsigned int>(keyBytes.size()));

    // הצפנת ההודעה
    return aes.encrypt(message.c_str(), static_cast<unsigned int>(message.size()));
}

std::string decryptAES(const std::string& encryptedMessage, const std::string& key) {
    // בדיקת גודל המפתח (AES תומך רק ב-16, 24, 32 בתים)
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::invalid_argument("Invalid AES key size. Must be 16, 24, or 32 bytes.");
    }

    // המרת מחרוזת למערך `unsigned char`
    std::vector<unsigned char> keyBytes(key.begin(), key.end());

    // יצירת מופע פענוח
    AESWrapper aes(keyBytes.data(), static_cast<unsigned int>(keyBytes.size()));

    // פענוח ההודעה
    return aes.decrypt(encryptedMessage.c_str(), static_cast<unsigned int>(encryptedMessage.size()));
}
