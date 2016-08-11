/** \file node_auth.c
* \brief client and host high-level API for PKI node authentication with ATECC508A
*
* Copyright (c) 2015 Atmel Corporation. All rights reserved.
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
 */ 

#include "node_auth.h"
#include "cert_def_1_signer.h"
#include "cert_def_2_device.h"
#include <security/libraries/cryptoauthlib/atcacert/atcacert_client.h>
#include <security/libraries/cryptoauthlib/atcacert/atcacert_host_hw.h>
#include <security/libraries/cryptoauthlib/basic/atca_helpers.h>



#include <stdio.h>

#include <sming/services/HexDump/HexDump.h>

#include "NodeCommands.h"
#include "user_config.h"
#include <SmingCore.h>


#include "../sming/services/WebHelpers/base64.h"
#include "../sming/services/WebHelpers/escape.h"
//#include "../sming/services/ArduinoJson/includ/ArduinoJson/DynamicJsonBuffer.hpp"
Timer sendTimer;
String url = "10.10.1.2:3000/";
extern HttpClient clientHttp;


extern HexDump dump;

/** \defgroup auth Node authentication stages for node-auth-basic example
 *
 * \brief
 *   These methods implement each phase of the authentication example.
 *   If you would like to follow a particular phase with a code walk through,
 *   you can follow each of the phases from client-provision through host-verify-resp.
 *   Each phase is initiated with a console command so you can control the progress
 *   through the example.
 *
@{ */

/** \brief global storage for signer certificate */
uint8_t g_signer_cert[512];
size_t  g_signer_cert_size = sizeof(g_signer_cert);
char g_cert_defEncoded[1024];
char g_responseEncoded[256];

/** \brief global storage for device certificate */
uint8_t g_device_cert[1024];
size_t  g_device_cert_size = sizeof(g_device_cert);

/** \brief global storage for the challenge data to sign by the device */
uint8_t g_challengeBase64[64];
uint8_t g_challenge[32];

uint8_t g_response[64];

extern uint8_t g_signer_ca_public_key[64];



void onDataSent(HttpClient& client, bool successful)
{
     if (successful){
            Serial.println("Success sent**********");
            sendTimer.stop();
     }else{
            Serial.println("Failed**************");
            // Interupt timer after several trays????
            return;
     }

      String response = client.getResponseString();
      Serial.println("Server response: '" + response + "'");

      String json = client.getResponseString();
      DynamicJsonBuffer jsonBuffer;
      JsonObject& root = jsonBuffer.parseObject(json);

      	//TODO _LL get the params out of the json
      	String chal= root["challenge"];
      	//Serial.println("Server Chaleng: '" + chal + "'");
      	//memcpy(g_challengeBase64,root["challenge"], 32);

      	base64_decode(64, (const char*)g_challengeBase64,32,g_challenge);

      	// client_generate_response();
}

/*
int sendRotCert(){

		DynamicJsonBuffer jsonBuffer;
		JsonObject& root = jsonBuffer.createObject();
		root["authStep"] = "host-chain-verify";
		root["cert"]= g_cert_defEncoded;

	   // clientHttp.downloadString(url +"?asdf=1234&sender=esp",onDataSent); // get

		String tempString;
		root.printTo(tempString);
		clientHttp.setPostBody(tempString);
	  	clientHttp.setRequestContentType("application/json");//application/json   text/plain
	  	clientHttp.downloadString(url ,onDataSent);
}*/



/** \brief This client role method demonstrates how to read cert data stored in the ATECC508A and reconstruct
 * a full X.509 cert in DER format.  Because this is an example, it prints the reconstructed cert
 * data to the console in ASCII hex format.
 */

int client_rebuild_certs(void)//
{
    int ret = 0;
    char disp_str[1500];
    int disp_size = sizeof(disp_str);
    uint8_t signer_public_key[64];
    
    g_signer_cert_size = sizeof(g_signer_cert);
	ret = atcacert_read_cert(&g_cert_def_1_signer, g_signer_ca_public_key, g_signer_cert, &g_signer_cert_size);
    if (ret != ATCACERT_E_SUCCESS) return ret;
    

    disp_size = sizeof(disp_str);
    atcab_bin2hex( g_signer_cert, g_signer_cert_size, disp_str, &disp_size);
   // printf("CLIENT: Rebuilt Signer Certificate:");
	//dump.print(g_signer_cert, g_signer_cert_size);		// Print char aray printen ******

    
    ret = atcacert_get_subj_public_key(&g_cert_def_1_signer, g_signer_cert, g_signer_cert_size, signer_public_key);
    if (ret != ATCACERT_E_SUCCESS) return ret;
    
    g_device_cert_size = sizeof(g_device_cert);
    ret = atcacert_read_cert(&g_cert_def_2_device, signer_public_key, g_device_cert, &g_device_cert_size);
    if (ret != ATCACERT_E_SUCCESS) return ret;
    
//    disp_size = sizeof(disp_str);
//    atcab_bin2hex( g_device_cert, g_device_cert_size, disp_str, &disp_size);
    //printf("CLIENT: Rebuilt Device Certificate: ");
	//dump.print(g_device_cert, g_device_cert_size);
    

    int encodeSize= sizeof(g_cert_defEncoded);
  	int len = base64_encode(g_device_cert_size, g_device_cert, encodeSize, g_cert_defEncoded);
  	//printf("encode Size: "+ encodeSize);
  	//dump.print((unsigned char*)g_cert_defEncoded, len);
  //  printf(g_cert_defEncoded); //gibt nur den pointer aus


  	//Oportuity the have several trys
    //sendTimer.initializeMs(2000, sendData).start();

	DynamicJsonBuffer jsonBuffer;
	JsonObject& root = jsonBuffer.createObject();
	root["authStep"] = "host-chain-verify";
	root["cert"]= g_cert_defEncoded;
	// clientHttp.downloadString(url +"?asdf=1234&sender=esp",onDataSent); // get

	String tempString;
	root.printTo(tempString);
	clientHttp.setPostBody(tempString);
	clientHttp.setRequestContentType("application/json");//application/json   text/plain
	clientHttp.downloadString(url ,onDataSent);

    return 0;
}



/** \brief This client role method signs the challenge and returns the signature to the host.  For
 * example purposes, the signature is contained in a global variable g_response.
 */

int client_generate_response(void)
{
    int ret = 0;
//    char disp_str[256];
//    int disp_size = sizeof(disp_str);

    printf("CLIENT: Use previous generated challenge:");
	dump.print(g_challenge, sizeof(g_challenge));

    ret = atcacert_get_response(g_cert_def_2_device.private_key_slot, g_challenge, g_response);
    if (ret != ATCACERT_E_SUCCESS) return ret;
//    disp_size = sizeof(disp_str);
//    atcab_bin2hex(g_response, sizeof(g_response), disp_str, &disp_size);
    printf("CLIENT: Calculated response to host challenge:");
	dump.print(g_response, sizeof(g_response));
    
	  int respLength= sizeof(g_response); //1024;
	  printf(""+ respLength);
	  	base64_encode(respLength, g_response, respLength*4, g_responseEncoded);
	//*******************************************************************
	//Send Respons

	  	DynamicJsonBuffer jsonBuffer;
	  	JsonObject& root = jsonBuffer.createObject();
	  	root["authStep"] = "host-verify-resp";
	  	root["resp"] ="thsi is my respons";
	  	//root["resp"] =g_responseEncoded;

	  	String tempString;
	  	root.printTo(tempString);
	  			//setPostBody(tempString);
	    clientHttp.setPostBody(tempString);// post
	    clientHttp.setRequestContentType("application/json");//application/json   text/plain
	    clientHttp.downloadString(url ,onDataSent);

	    printf("Json String: " );
	    Serial.println(tempString);
	     //Serial.print


	    printf("Chalenge Resp sent++++++++++++++++++++++++++++++++++++++++++++++++");

    return 0;
}




/** @} */
