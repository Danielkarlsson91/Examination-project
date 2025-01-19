#include "communication.h"
#include <Arduino.h>

#define BAUDRATE 115200

bool communication_init(void)
{
    Serial.begin(BAUDRATE);
    return Serial ? true : false;
    ;
}

bool communication_write(const uint8_t *data, size_t data_len)
{
    return (data_len == Serial.write(data, data_len));
}

size_t communication_read(uint8_t *buf, size_t buf_len)
{
    while (0 == Serial.available())
    {
        ;
    }
    return Serial.readBytes(buf, buf_len);
}