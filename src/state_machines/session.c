/*
 *  session.c
 *
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2010.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  
 *  https://sourceforge.net/projects/openpana/
 */
#include <stdlib.h>
#include <netinet/in.h> //Function htons()
#include <stdio.h>
#include <string.h>
#include "session.h"
#include "statemachine.h"
#include "../panamessages.h"
#include "../panautils.h"

void initSession(pana_ctx * pana_session) {
//FIXME No iniciar las variables que se inician en la máquina de estados
// ya que se estaría reinicializando y es inútil.

	// Load variables from xml config file
#ifdef ISCLIENT
	load_config_client();
#endif

#ifdef ISSERVER
	load_config_server();
#endif
    // Init common
    pana_session->RTX_TIMEOUT = 0;
    pana_session->RTX_COUNTER = 0;
    pana_session->NONCE_SENT = 0;
    pana_session->REAUTH = 0;
    pana_session->TERMINATE = 0;
    pana_session->PANA_PING = 0;
    pana_session->SESS_TIMEOUT = 0;
    pana_session->ANY = 0;
    pana_session->CURRENT_STATE = INITIAL;
    pana_session->LAST_MESSAGE = NULL;
    pana_session->retr_msg = NULL;
    pana_session->PNR.flags = 0;
    pana_session->PNR.receive = 0;
    pana_session->PNR.result_code = -1;
    pana_session->PNA.flags = 0;
    pana_session->PNA.receive = 0;
    pana_session->PNA.result_code = -1;
    pana_session->PAR.flags = 0;
    pana_session->PAR.receive = 0;
    pana_session->PAR.result_code = -1;
    pana_session->PTR.flags = 0;
    pana_session->PTR.receive = 0;
    pana_session->PTR.result_code = -1;
    pana_session->PTA.flags = 0;
    pana_session->PTA.receive = 0;
    pana_session->PTA.result_code = -1;
    pana_session->PAN.flags = 0;
    pana_session->PAN.receive = 0;
    pana_session->PAN.result_code = -1;
    pana_session->PCI.flags = 0;
    pana_session->PCI.receive = 0;
    pana_session->PCI.result_code = -1;
    pana_session->RTX_MAX_NUM = REQ_MAX_RC;

    pana_session->key_len = 0;
    pana_session->msk_key = NULL;

    pana_session->I_PAN = NULL;
    pana_session->I_PAR = NULL;

    pana_session->PaC_nonce = NULL;
    pana_session->PAA_nonce = NULL;
    pana_session->key_id = NULL;

    //Init the Retransmission Times
    pana_session->IRT = 1; //See rfc 3315
    //Calculates an random value as RAND value
    struct timeval seed;
    gettimeofday(&seed, NULL);
    srand(seed.tv_usec); //initialize random generator using usecs
    float aux_random = rand();
    float random = ((float)aux_random * 0.00000000001); //Generating decimal values
    
    pana_session->RAND = random;
    pana_session->MRC = REQ_MAX_RC; //See rfc 3315
    pana_session->MRT = REQ_MAX_RT; //See rfc 3315
    pana_session->MRD = 0; //See rfc 3315

    pana_session->key_id_length = 4;

    
    pana_session->avp_data[AUTH_AVP] = NULL;
    pana_session->avp_data[EAPPAYLOAD_AVP] = NULL;
    pana_session->avp_data[KEYID_AVP] = NULL;
    pana_session->avp_data[RESULTCODE_AVP] = NULL;
    pana_session->avp_data[NONCE_AVP] = NULL;
    pana_session->avp_data[SESSIONLIFETIME_AVP] = NULL;
    pana_session->avp_data[TERMINATIONCAUSE_AVP] = NULL;
    pthread_mutex_init(&(pana_session->mutex), NULL);

    // Init client's variables
#ifdef ISCLIENT //Include session variables only for PANA clients
    pana_session->client_ctx.FAILED_SESS_TIMEOUT = FAILED_SESS_TIMEOUT_CONFIG; //Until the authentication is done, the client doesn't know 

																			   // his session expiration time


    //FIXME: De momento, tanto cliente como servidor solamente tienen el prf_alg y el integrity algorithm estáticos
    // definidos aquí.
    pana_session->avp_data[PRFALG_AVP] = (void*) PRF_HMAC_SHA1; //see rfc4306 page 50
    pana_session->avp_data[INTEGRITYALG_AVP] = (void*) AUTH_HMAC_SHA1_160; //see rfc4306 page 50
    
    pana_session->client_ctx.AUTH_USER = 0;

    pana_session->src_port = SRCPORT;
    pana_session->dst_port = DSTPORT;
    
	pana_session->eap_ll_dst_addr.sin_family = AF_INET;
    pana_session->eap_ll_dst_addr.sin_port = htons(DSTPORT);
    pana_session->eap_ll_dst_addr.sin_addr.s_addr = inet_addr(DESTIP); 
    /* Client's sequence number and session id is set to 0, the first message it's
     * always supposed to be a PCI. */
    pana_session->SEQ_NUMBER = 0;
    pana_session->session_id = 0;
	
    //Inicia el usuario eap
    eap_peer_init(&(pana_session->eap_ctx), pana_session,USER,PASSWORD,CA_CERT,CLIENT_CERT,CLIENT_KEY,PRIVATE_KEY,FRAG_SIZE);

#endif

#ifdef ISSERVER //Include session variables only for PANA servers


	//FIXME: De momento, tanto cliente como servidor solamente tienen el prf_alg y el integrity algorithm estáticos
    // definidos aquí.
    pana_session->avp_data[PRFALG_AVP] = (void*) PRF_HMAC_SHA1; //see rfc4306 page 50
    pana_session->avp_data[INTEGRITYALG_AVP] = (void*) AUTH_HMAC_SHA1_160; //see rfc4306 page 50
    
	pana_session->eap_ll_dst_addr.sin_family = AF_INET;
    pana_session->src_port = SRCPORT;
    
    pana_session->LIFETIME_SESS_TIMEOUT = LIFETIME_SESSION_TIMEOUT_CONFIG;
    pana_session->server_ctx.OPTIMIZED_INIT = 0;
    pana_session->server_ctx.PAC_FOUND = 0;
    pana_session->server_ctx.REAUTH_TIMEOUT = 0;
    pana_session->RTX_COUNTER_AAA = 0;
    
    //RCF 5191 11.1: Secuence numbers are randomly initialized at the
    //beginning of the session.
    pana_session->SEQ_NUMBER = rand(); 
	
	pana_session->server_ctx.global_key_id = NULL;
    eap_auth_init(&(pana_session->eap_ctx), pana_session);
#endif
}

void updateSession(char *message, pana_ctx *pana_session) {
	#ifdef DEBUG
	fprintf(stderr,"DEBUG: Update session with message:\n");
	debug_pana((pana*) message);
	#endif
	
    resetSession(pana_session);
    pana * msg = (pana*) message;
    short flags = ntohs(msg->flags);
    short type = ntohs(msg->msg_type);
    #ifdef ISCLIENT
	// Update the session id to the client only in the first message from
    // the PAA during authentication, it has to be a PAR message with
    // S_FLAG active
    if ((flags & S_FLAG) && (flags & R_FLAG) && ntohs(msg->msg_type) == PAR_MSG) {
		pana_session->session_id = ntohl(msg->session_id);
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Client's session updated with Session Id from PAA: %d\n",pana_session->session_id);
		#endif
	}
	#endif
    
    //If the message is not valid, discard it.
    if (checkPanaMessage(msg, pana_session) == 0) {		
        return;
    }
	
    printf("PANA: Received %s message.\n", getMsgName(ntohs(msg->msg_type)));
	//Update the last received message
	if(pana_session->LAST_MESSAGE != NULL){
		//FIXME Hay que ponerlo
		//free(pana_session->LAST_MESSAGE);
	}
    pana_session->LAST_MESSAGE = message;
    
    // Detect message type and flags
    //FIXME Falta comprobar que sea el primer mensaje (flagS) o ponerlo en la maquina de estados
    //FIXME: Falta detectar el result-code
    char * attribute = getAvp(message, PRFALG_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));

		int number = Hex2Dec(value, 4);//FIXME: Magic number (4 porque es el tamaño del campo value)
		if (number != PRF_HMAC_SHA1) {
			fprintf(stderr, "ERROR: The prf algorithm specified: %d, is not supported\n", PRF_HMAC_SHA1);
			exit(0);
		}
        pana_session->prf_alg = number;
    }
	
	attribute = getAvp(message, INTEGRITYALG_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));

		int number = Hex2Dec(value, 4);//FIXME: Magic number (4 porque es el tamaño del campo value)
		if (number != AUTH_HMAC_SHA1_160) {
			fprintf(stderr, "ERROR: The integrity algorithm specified: %d, is not supported\n", AUTH_HMAC_SHA1_160);
			exit(0);
		}
        pana_session->integ_alg = number;
    }
    
    attribute = getAvp(message, SESSIONLIFETIME_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));

		int number = Hex2Dec(value, 4);//FIXME: Magic number (4 porque es el tamaño del campo value)
        pana_session->LIFETIME_SESS_TIMEOUT = number;
	}

#ifdef DEBUG
    fprintf(stderr,"DEBUG: Session updated with message: \n");
#endif

    if (type == PCI_MSG) { // PCI
        pana_session->PCI.receive = TRUE;
        pana_session->PCI.flags = flags;
#ifdef DEBUG
        fprintf(stderr,"DEBUG: PCI \n");
#endif
    } else if (type == PAR_MSG) { //Authentication type Message, it could also be PAN_MSG
		//debug_pana(msg);
        //Check if it contains the Nonce AVP and update its value
        if (existAvp(message, "Nonce")) { //Depending if you are server or client
#ifdef ISSERVER
			fprintf(stderr,"DEBUG: Server's detected a Nonce AVP.\n");
			if(pana_session->PaC_nonce != NULL){
				free(pana_session->PaC_nonce);
			}
			pana_session->PaC_nonce = malloc(ntohs(((pana*)message)->msg_length));
			memcpy(pana_session->PaC_nonce,message,(ntohs(((pana*)message)->msg_length)));
#endif
#ifdef ISCLIENT
			if(pana_session->PAA_nonce != NULL){
				free(pana_session->PAA_nonce);
			}
			pana_session->PAA_nonce = malloc(ntohs(((pana*)message)->msg_length));
			memcpy(pana_session->PAA_nonce,message,(ntohs(((pana*)message)->msg_length)));
#endif
        }
        #ifdef DEBUG
        else{
			fprintf(stderr,"DEBUG: There isn't any Nonce AVP in the message.\n");
		}
		#endif

        if (flags & R_FLAG) { //PAR
            pana_session->PAR.receive = TRUE;
            pana_session->PAR.flags = flags;

            //If the PAR is the first one (bit S enabled), it must be
            //saved in the pana session to be used in AUTH key generation
            //Also you must keep the sequence number
            if (flags & S_FLAG) {
				if(pana_session->I_PAR != NULL){
					free(pana_session->I_PAR);
				}
                pana_session->I_PAR = malloc(ntohs(msg->msg_length));
                memcpy(pana_session->I_PAR,message,ntohs(msg->msg_length));
                pana_session->SEQ_NUMBER = ntohl(msg->seq_number);
            }

            //Check if it contains the Key-Id AVP and update its value
            //There's a key-id needed to be updated only when C-Flag is enabled
            if ((flags & C_FLAG) && existAvp(message, "Key-Id")) {

                avp_pana * elmnt = (avp_pana*) getAvp(message, KEYID_AVP);

                //elmnt is pointed to Key-Id AVP, the key-id value is copied
                if (pana_session->key_id == NULL) {
					int avpsize = ntohs(elmnt->length);
                    pana_session->key_id = malloc(avpsize);
                    if(pana_session->key_id == NULL){
						fprintf(stderr,"ERROR: Out of memory.\n");
						exit(1);
					}
                    memcpy(pana_session->key_id, ((char*)elmnt)+sizeof(avp_pana),avpsize);
                }
#ifdef DEBUG
                else {
                    fprintf(stderr, "DEBUG: Generado Key-Id cuando no hace falta en cliente?.\n");
                }
#endif
            }
#ifdef DEBUG
            fprintf(stderr,"DEBUG: PAR \n");
#endif
        } else { // PAN
            pana_session->PAN.receive = TRUE;
            pana_session->PAN.flags = flags;

            //If the PAN is the first one (bit S enabled), it must be
            //saved in the pana session to be used in AUTH key generation
            if (flags & S_FLAG) {
				if(pana_session->I_PAN != NULL){
					free(pana_session->I_PAN);
				}
                pana_session->I_PAN = malloc(ntohs(msg->msg_length));
                memcpy(pana_session->I_PAN,message,ntohs(msg->msg_length));
                pana_session->SEQ_NUMBER = ntohl(msg->seq_number);
            }
#ifdef DEBUG
            fprintf(stderr,"DEBUG: PAN \n");
#endif
        }
    } else if (type == PTA_MSG) { //Transmission Message PTR or PTA
        if (flags & R_FLAG) { //PTR
            pana_session->PTR.receive = TRUE;
            pana_session->PTR.flags = flags;
#ifdef DEBUG
            fprintf(stderr,"DEBUG: PTR \n");
#endif
        } else { // PTA
            pana_session->PTA.receive = TRUE;
            pana_session->PTA.flags = flags;
#ifdef DEBUG
            fprintf(stderr,"DEBUG: PTA \n");
#endif
        }
    } else if (type == PNA_MSG) { //Notification Message PNR or PNA
        if (flags & R_FLAG) { //PNR
            pana_session->PNR.receive = TRUE;
            pana_session->PNR.flags = flags;
#ifdef DEBUG
            fprintf(stderr,"DEBUG: PNR \n");
#endif
        } else { // PNA
            pana_session->PNA.receive = TRUE;
            pana_session->PNA.flags = flags;
#ifdef DEBUG
            fprintf(stderr,"DEBUG: PNA \n");
#endif
        }
    }

    //FIXME: Faltan el resto de variables, cuales?
	
}

void resetSession(pana_ctx *pana_session) {

    // Reset common
    pana_session->RTX_TIMEOUT = 0;
    pana_session->REAUTH = 0;
    pana_session->TERMINATE = 0;
    pana_session->PANA_PING = 0;
    pana_session->SESS_TIMEOUT = 0;
    pana_session->ANY = 0;
    pana_session->PNR.flags = 0;
    pana_session->PNR.receive = 0;
    pana_session->PNR.result_code = -1;
    pana_session->PNA.flags = 0;
    pana_session->PNA.receive = 0;
    pana_session->PNA.result_code = -1;
    pana_session->PAR.flags = 0;
    pana_session->PAR.receive = 0;
    pana_session->PAR.result_code = -1;
    pana_session->PTR.flags = 0;
    pana_session->PTR.receive = 0;
    pana_session->PTR.result_code = -1;
    pana_session->PTA.flags = 0;
    pana_session->PTA.receive = 0;
    pana_session->PTA.result_code = -1;
    pana_session->PAN.flags = 0;
    pana_session->PAN.receive = 0;
    pana_session->PAN.result_code = -1;
    pana_session->PCI.flags = 0;
    pana_session->PCI.receive = 0;
    pana_session->PCI.result_code = -1;
    pana_session->RTX_MAX_NUM = REQ_MAX_RC;

    // Init client's variables
#ifdef ISCLIENT //Include session variables only for PANA clients
    pana_session->client_ctx.AUTH_USER = 0;
#endif

#ifdef ISSERVER //Include session variables only for PANA servers
    pana_session->server_ctx.OPTIMIZED_INIT = 0;
    pana_session->server_ctx.PAC_FOUND = 0;
    pana_session->server_ctx.REAUTH_TIMEOUT = 0;
	pana_session->RTX_COUNTER_AAA = 0;
#endif
}
