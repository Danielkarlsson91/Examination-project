#include <Arduino.h>
#include "session.h"

#define STR(x) #x
#define STRINGIPY(x) STR(x)

#define RED_PIN GPIO_NUM_21
#define GREEN_PIN GPIO_NUM_4
#define BLUE_PIN GPIO_NUM_5

static void set status(int status)
{
  digitalWrite(RED_PIN, LOW);
  digitalWrite(GREEN_PIN, LOW);
  digitalWrite(BLUE_PIN, LOW);

  switch (status)
  {
  case SESSION_ERROR:
    digitalWrite(RED_PIN, HIGH);
    break;

  case SESSION_WARNING:
    digitalWrite(BLUE_PIN, HIGH);
    break;

  default:
    digitalWrite(GREEN_PIN, HIGH);
    break;
  }
}

void setup()
{
  pinMode(GPIO_NUM_32, OUTPUT);
  pinMode(RED_PIN, OUTPUT);
  pinMode(GREEN_PIN, OUTPUT);
  pinMode(BLUE_PIN, OUTPUT);

  set_status(SESSION_OKAY);

  if (SESSION_OKAY != session_init(STRINGIPY()))
  {
    set_status(SESSION_ERROR);

    while (1)
    {
      ;
    }
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
    static uint8_t state = LOW;
    state = (state == LOW) ? HIGH : LOW;
    digitalWrite(GPIO_NUM_32, state);
    request = (state == digitalRead(GPIO_NUM_32)) ? session_send_relay_state;

    break;

  default:
    break;
  }

  set_status(request);
}