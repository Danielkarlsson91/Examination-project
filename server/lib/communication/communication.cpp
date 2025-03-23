#include "communication.h"
#include <Arduino.h>

bool communication_init(const int comparam)
{
    Serial.begin(comparam);

    return Serial;
}

bool communication_write(const uint8_t *data, size_t dlen)
{
    return (dlen == Serial.write(data, dlen));
}

size_t communication_read(uint8_t *buf, size_t blen)
{
    while (0 == Serial.available())
    {
        ;
    }
    return Serial.readBytes(buf, blen);
}

void communication_close(void)
{
    Serial.end();
}