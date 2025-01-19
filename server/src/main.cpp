#include <Arduino.h>
#include "session.h"
#include "communication.h"

#define TOGGLE_RELAY 0x03
#define LED_ON 0x01
#define LED_OFF 0x00

void setup()
{
  pinMode(21, OUTPUT);
  communication_init();
}

void loop()
{
  uint8_t command;
  size_t len = communication_read(&command, sizeof(command));

  if (len > 0)
  {
    if (command == TOGGLE_RELAY)
    {
      int currentstate = digitalRead(21);
      int newState = !currentState;
      digitalWrite(21, newState);

      uint_t response = (newState == HIGH) ? LED_ON : LED_OFF;
      communication_write(&response, sizeof(response));
    }
    else
    {
    }
  }
}
