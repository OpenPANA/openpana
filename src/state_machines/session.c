/**
 * @file session.c
 * @brief Functions to manage PANA sessions.
 **/
/*
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

    // Init common variables to PaC & PAA
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
    srand(getTime()); //initialize random generator using time
    float aux_random = rand();
    float random = ((float)aux_random * 0.00000000001); //Generating decimal values
    
    pana_session->RAND = random;
    pana_session->MRC = REQ_MAX_RC; //See rfc 3315
    pana_session->MRT = REQ_MAX_RT; //See rfc 3315
    pana_session->MRD = 0; //See rfc 3315

	// Updated key identifier's length
    pana_session->key_id_length = 4;

    // Init the data structure needed to build the avp carried on the PANA messages.
    pana_session->avp_data[AUTH_AVP] = NULL;
    pana_session->avp_data[EAPPAYLOAD_AVP] = NULL;
    pana_session->avp_data[KEYID_AVP] = NULL;
    pana_session->avp_data[RESULTCODE_AVP] = NULL;
    pana_session->avp_data[NONCE_AVP] = NULL;
    pana_session->avp_data[SESSIONLIFETIME_AVP] = NULL;
    pana_session->avp_data[TERMINATIONCAUSE_AVP] = NULL;
    pthread_mutex_init(&(pana_session->mutex), NULL);

	//FIXME: De momento, tanto cliente como servidor solamente tienen el prf_alg y el integrity algorithm estáticos
    // definidos aquí.
    pana_session->avp_data[PRFALG_AVP] = (void*) PRF_HMAC_SHA1; //see rfc4306 page 50
    pana_session->avp_data[INTEGRITYALG_AVP] = (void*) AUTH_HMAC_SHA1_160; //see rfc4306 page 50
    
    // Init client's variables
#ifdef ISCLIENT //Include session variables only for PANA clients
    pana_session->client_ctx.FAILED_SESS_TIMEOUT = FAILED_SESS_TIMEOUT_CONFIG; //Until the authentication is done, the client doesn't know his session expiration time
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
	
    //Init the EAP user
    //FIXME: warning: passing argument 9 of ‘eap_peer_init’ makes pointer
    //from integer without a cast: expected ‘char *’ but argument is of type ‘int’. Pedro: ¿Ya está solucionado?
    eap_peer_init(&(pana_session->eap_ctx), pana_session,USER,PASSWORD,CA_CERT,CLIENT_CERT,CLIENT_KEY,PRIVATE_KEY,FRAG_SIZE);

#endif

#ifdef ISSERVER //Include session variables only for PANA servers
	pana_session->eap_ll_dst_addr.sin_family = AF_INET;
    pana_session->src_port = SRCPORT;
    
    pana_session->LIFETIME_SESS_TIMEOUT = LIFETIME_SESSION_TIMEOUT_CONFIG;
    pana_session->server_ctx.OPTIMIZED_INIT = 0;
    pana_session->server_ctx.PAC_FOUND = 0;
    pana_session->server_ctx.REAUTH_TIMEOUT = 0;
    pana_session->server_ctx.RTX_COUNTER_AAA = 0;
    
    //RCF 5191 11.1: Secuence numbers are randomly initialized at the
    //beginning of the session.
    pana_session->SEQ_NUMBER = rand(); //rand has been initialized before
	
	pana_session->server_ctx.global_key_id = NULL;
	// Init EAP authenticator.
    eap_auth_init(&(pana_session->eap_ctx), pana_session, CA_CERT, SERVER_CERT, SERVER_KEY);
#endif
}

void updateSession(char *message, pana_ctx *pana_session) {
	pana_debug("Update session with the following message:");
	debug_msg((pana*) message);

	// Reset the session for being updated.
    resetSession(pana_session);

    // Get the last message and its information.
    pana * msg = (pana*) message;
    short flags = ntohs(msg->flags);
    short type = ntohs(msg->msg_type);
    
    #ifdef ISCLIENT
	// Update the session id to the client only in the first message from
    // the PAA during authentication, it has to be a PAR message with
    // S_FLAG active
    if ((flags & S_FLAG) && (flags & R_FLAG) && ntohs(msg->msg_type) == PAR_MSG) {
		pana_session->session_id = ntohl(msg->session_id);
		pana_debug("Client's session updated with Session Id from PAA: %d",pana_session->session_id);
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
		//XFREE(pana_session->LAST_MESSAGE);
	}
    pana_session->LAST_MESSAGE = message;
    
    // Detect message type and flags
    //FIXME Falta comprobar que sea el primer mensaje (flagS) o ponerlo en la maquina de estados
    //FIXME: Falta detectar el result-code

    // Check if the message received contains the PRF algorithm AVP
    char * attribute = getAvp(message, PRFALG_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));

		int number = Hex2Dec(value, PRF_AVP_VALUE_LENGTH);
		if (number != PRF_HMAC_SHA1) {
			pana_fatal("The prf algorithm specified: %d, is not supported\n", number);
		}

		// Updated the PRF algorithm negociated.
        pana_session->prf_alg = number;
    }

	// Check if the message received contains the Integrity algorithm AVP
	attribute = getAvp(message, INTEGRITYALG_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));

		int number = Hex2Dec(value, INTEG_AVP_VALUE_LENGTH);
		if (number != AUTH_HMAC_SHA1_160) {
			pana_fatal("The integrity algorithm specified: %d, is not supported\n", number);
		}

		// Updated the Integrity algoritm negociated.
        pana_session->integ_alg = number;
    }

    // Check if the message received contains the Session lifetime AVP
    attribute = getAvp(message, SESSIONLIFETIME_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));

		int number = Hex2Dec(value, SESSLIFETIME_AVP_VALUE_LENGTH);

		// Updated the session lifetime value generated by PAA
        pana_session->LIFETIME_SESS_TIMEOUT = number;
	}
	
	pana_debug("Session updated with message:");

    if (type == PCI_MSG) { // PCI
        pana_session->PCI.receive = TRUE;
        pana_session->PCI.flags = flags;
        pana_debug("PCI");
    } else if (type == PAR_MSG) { //Authentication type Message, it could also be PAN_MSG
		//debug_msg(msg);
        //Check if it contains the Nonce AVP and update its value
        if (existAvp(message, "Nonce")) { //Depending if you are server or client
			pana_debug("It's been detected a Nonce AVP");
#ifdef ISSERVER
			XFREE(pana_session->PaC_nonce);
			// The PAA saves the Nonce value generated by the PaC 
			pana_session->PaC_nonce = XMALLOC(char,ntohs(((pana*)message)->msg_length));
			memcpy(pana_session->PaC_nonce,message,(ntohs(((pana*)message)->msg_length)));
#endif
#ifdef ISCLIENT
			XFREE(pana_session->PAA_nonce);
			// The PaC saves the Nonce value generated by the PAA 
			pana_session->PAA_nonce = XMALLOC(char,ntohs(((pana*)message)->msg_length));
			memcpy(pana_session->PAA_nonce,message,(ntohs(((pana*)message)->msg_length)));
#endif
        }
        else{
			pana_debug("There isn't any Nonce AVP in the message");
		}

        if (flags & R_FLAG) { //PAR
            pana_session->PAR.receive = TRUE;
            pana_session->PAR.flags = flags;

            //If the PAR is the first one (bit S enabled), it must be
            //saved in the pana session to be used in AUTH key generation
            //Also you must keep the sequence number
            if (flags & S_FLAG) {
				XFREE(pana_session->I_PAR);
                pana_session->I_PAR = XMALLOC(char,ntohs(msg->msg_length));
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
                    pana_session->key_id = XMALLOC(char,avpsize);
                    memcpy(pana_session->key_id, ((char*)elmnt)+sizeof(avp_pana),avpsize);
                }
                else {
					pana_debug("Generated Key-Id when it's not needed by client?");
                }
            }
            pana_debug("PAR");
        } else { // PAN
            pana_session->PAN.receive = TRUE;
            pana_session->PAN.flags = flags;

            //If the PAN is the first one (bit S enabled), it must be
            //saved in the pana session to be used in AUTH key generation
            if (flags & S_FLAG) {
				XFREE(pana_session->I_PAN);
                pana_session->I_PAN = XMALLOC(char,ntohs(msg->msg_length));
                memcpy(pana_session->I_PAN,message,ntohs(msg->msg_length));
                pana_session->SEQ_NUMBER = ntohl(msg->seq_number);
            }
            pana_debug("PAN");
        }
    } else if (type == PTA_MSG) { //Transmission Message PTR or PTA
        if (flags & R_FLAG) { //PTR
            pana_session->PTR.receive = TRUE;
            pana_session->PTR.flags = flags;
            pana_debug("PTR");
        } else { // PTA
            pana_session->PTA.receive = TRUE;
            pana_session->PTA.flags = flags;
            pana_debug("PTA");
        }
    } else if (type == PNA_MSG) { //Notification Message PNR or PNA
        if (flags & R_FLAG) { //PNR
            pana_session->PNR.receive = TRUE;
            pana_session->PNR.flags = flags;
            pana_debug("PNR");
        } else { // PNA
            pana_session->PNA.receive = TRUE;
            pana_session->PNA.flags = flags;
            pana_debug("PNA");
        }
    }

    //FIXME: Faltan el resto de variables, cuales?
	
}

void resetSession(pana_ctx *pana_session) {

    // Reset common variables between PaC & PAA
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
	pana_session->server_ctx.RTX_COUNTER_AAA = 0;
#endif
}
