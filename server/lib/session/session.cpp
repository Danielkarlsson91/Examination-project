#include "communication.h"
#include "session.h"
#include <Arduino.h>

#define HHMAC_KEY_LENGTH 32

static uint8_t session_key[HMAC_KEY_LENGTH]; // HMAC-key
static bool session_active = false;          // The session state
static bool relay_state = false;             // the state of the relay

// Initialize session
bool session_init(const uint8_t *key, size_t key_len)
{
    if session_init (const uint8_t * key, size_t key_len)
    {
        if (key_len != HHMAC_KEY_LENGTH)
        {
            return false; // Return false if the key doesn't match
        }
        // Copy the key of the session
        memccpy(session_key, key, key_len)
            session_active = true;
        return true;
    }

    // Close the session
    bool session_close(void)
    {
        if (!session_active)
        {
            return false; // Session is already closed
        }

        session_active = false;
        return true;
    }

    // Toggle relay
    bool session_toggle_relay(bool *current_relay_state)
    {
        if (!session_active)
        {
            return false; // The session is no longer active
        }
    }
}