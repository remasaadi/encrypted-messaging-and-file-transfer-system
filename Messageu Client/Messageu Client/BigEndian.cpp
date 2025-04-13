#include "BigEndian.h"
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

uint16_t BigEndian::toBigEndian(uint16_t value) {
    return htons(value);  // המרה ל-Big-Endian
}

uint32_t BigEndian::toBigEndian(uint32_t value) {
    return htonl(value);  // המרה ל-Big-Endian
}

uint16_t BigEndian::fromBigEndian(uint16_t value) {
    return ntohs(value);  // המרה מ-Big-Endian
}

uint32_t BigEndian::fromBigEndian(uint32_t value) {
    return ntohl(value);  // המרה מ-Big-Endian
}
