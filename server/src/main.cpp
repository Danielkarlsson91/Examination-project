#include <Arduino.h>
#include "session.h"

#define LED_PIN GPIO_NUM_21
#define RELAY_PIN GPIO_NUM_32

void set_error(void)
{
  while (1)
  {
    digitalWrite(LED_PIN, HIGH);
    delay(200);
    digitalWrite(LED_PIN, LOW);
    delay(200);
  }
}

void setup()
{
  pinMode(LED_PIN, OUTPUT);
  pinMode(RELAY_PIN, OUTPUT);

  if (SESSION_OKAY != session_init(115200))
  {
    set_error();
  }
}

void loop()
{
  int request = session_request();

  switch (request)
  {
  case SESSION_ESTABLISH:
    request = session_establish();
    break;

  case SESSION_CLOSE:
    request = session_close();
    break;

  case SESSION_GET_TEMP:
    request = session_send_temperature(temperatureRead());
    break;

  case SESSION_TOGGLE_RELAY:
  {
    static uint8_t state = LOW;
    state = (state == LOW) ? HIGH : LOW;
    digitalWrite(GPIO_NUM_32, state);
    request = (state == digitalRead(GPIO_NUM_32)) ? session_send_relay_state(state) : SESSION_ERROR;
    break;
  }

  default:
    break;
  }

  if (request == SESSION_ERROR)
  {
    set_error();
  }
}