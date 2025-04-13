#pragma once
#include <string>
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "Files.h"
#include "KeysManagement.h"
#include "Messages.h"
#include "Requests.h"

// הצפנת הודעה עם AES
std::string encryptAES(const std::string& message, const std::string& key);
std::string decryptAES(const std::string& encryptedMessage, const std::string& key);
