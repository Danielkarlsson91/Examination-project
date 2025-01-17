#include <Arduino.h>
#include "session.h"

#define STR(x) 02
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
    case SESSION_ERROR
  }
}
