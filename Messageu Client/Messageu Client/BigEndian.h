#ifndef BIG_ENDIAN_H
#define BIG_ENDIAN_H

#include <cstdint>

class BigEndian {
public:
    static uint16_t toBigEndian(uint16_t value);
    static uint32_t toBigEndian(uint32_t value);
    static uint16_t fromBigEndian(uint16_t value);
    static uint32_t fromBigEndian(uint32_t value);
};

#endif // BIG_ENDIAN_H
