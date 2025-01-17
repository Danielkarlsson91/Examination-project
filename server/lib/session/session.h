#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stddef.h>

enum
{
    SESSION_CLOSE,
    SESSION_GET_TEMP,
    SESSION_ESTABLISH,
    SESSION_TOGGLE_RELAY,

    SESSION_OKAY,
    SESSION_ERROR,
    SESSION_WARNING,
};

int session_close(void);

int session_request(void);

int session_establish(void);

int session_send_error(void);

int session_init(const char *comparam);

int session_send_temperature(float temp);

int session_send_relay_state(uint8_t state);

#endif