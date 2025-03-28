#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <stdint.h>
#include <stddef.h>

bool communication_init(const int comparam);
bool communication_write(const uint8_t *data, size_t data_len);
size_t communication_read(uint8_t *buf, size_t buf_len);
void communication_close(void);

#endif