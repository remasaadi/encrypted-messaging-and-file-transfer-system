#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H

#include "Communication.h"
#include "KeysManagement.h"
#include <vector>
#include <string>

class FileTransfer {
private:
    Communication& comm;
    KeysManagement& keysManager; // הוספת גישה למנהל המפתחות
    std::string findClientIDByUsername(const std::string& username);
    std::string padMessage(const std::string& message, size_t blockSize = 16);
    std::string unpadMessage(const std::string& paddedMessage);


public:
    FileTransfer(Communication& comm, KeysManagement& keysManager);

    void sendFile(const std::string& target_id, const std::string& file_path);
    void handleIncomingFile(const std::string& sender_id, const std::vector<char>& encryptedContent);
};

#endif // FILE_TRANSFER_H
