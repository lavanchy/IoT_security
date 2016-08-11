/** \file Host driver for atca-ng test and development
 *
 * Copyright (C) 2012-2015 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */


#include <asf.h>
#include "cbuf.h"
#include "cryptoauthlib.h"
#include "cmd-processor.h"
#include "node_auth.h" //Temp for  client_rebuild_certs()


static ATCA_STATUS lockstatus(void)
{
	ATCA_STATUS status;
	bool dataIsLocked=0xff, cfgIsLocked=0xff;
	
	if ( (status = atcab_is_locked( LOCK_ZONE_CONFIG, &cfgIsLocked )) != ATCA_SUCCESS )
	printf("can't read cfg lock\r\n");
	else if ( (status = atcab_is_locked( LOCK_ZONE_DATA, &dataIsLocked )) != ATCA_SUCCESS )
	printf("can't read data lock\r\n");

	if ( status == ATCA_SUCCESS ) {
		printf("Config Zone Lock: %s\r\n", cfgIsLocked == 0x01 ? "locked" : "unlocked");
		printf("Data Zone Lock  : %s\r\n", dataIsLocked == 0x01 ? "locked" :"unlocked" );
	}
	
	return status;
}



int main(void)
{
	system_init();

	// Initialize interrupt vector table support.
	irq_initialize_vectors();

	// Enable interrupts
	cpu_irq_enable();

	stdio_usb_init();
			
	uint8_t ch;
    
    atcab_init( &cfg_ateccx08a_i2c_default );
	//lockstatus();
	//client_rebuild_certs();
	
	
	//******************LL Debug Sernum
	/*
	uint8_t serialnum[ATCA_SERIAL_NUM_SIZE];
	char displaystr[30];
	int displaylen = sizeof(displaystr);
	atcab_read_serial_number( serialnum );
	
	// dump serial num
	atcab_bin2hex(serialnum, ATCA_SERIAL_NUM_SIZE, displaystr, &displaylen );
	printf("\r\nserial number:\r\n%s\r\n", displaystr);
	//******************End Debug  */
	
	//uint8_t number[32];
	//atcab_random(number);
	
	while (true) { // original True
		ch = 0;
		if (udi_cdc_is_rx_ready())
			scanf("%c",&ch);
	
		if (ch) {
			printf("%c",ch); // echo to output
			if ( ch == 0x0d || ch == 0x0a ) {
				processCmd();
			} else {
				CBUF_Push( cmdQ, ch );  // queue character into circular buffer
			}
		}
	}
}
