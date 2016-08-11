/****
 * Sming Framework Project - Open Source framework for high efficiency native ESP8266 development.
 * Created 2015 by Skurydin Alexey
 * http://github.com/anakod/Sming
 * All files of the Sming Core are provided under the LGPL v3 license.
 ****/

#include "ESP8266EX.h"
#include "../core/Digital.h"

void EspDigitalPin::mode(uint8_t mode)
{
	pinMode(id, mode);
}

void EspDigitalPin::writeex(uint8_t val)
{
	digitalWrite(id, val);
}

uint8_t EspDigitalPin::readex()
{
	return digitalRead(id);
}
