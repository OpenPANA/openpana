/**
 * @file paamachine.c
 * @brief  Implementation of PAA's state machine specific functions.
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

#include "paamachine.h"
#include "statemachine.h"
#include "../panamessages.h"
#include "../panautils.h"

void initPaaTable(pana_ctx *pana_session) {
    initTable(); // Init the common state machine between pac and paa
    // Initialization Action
    
    //FIXME: A esta variable hay que ponerle el valor set/unset
    //Sacar a la configuración cuando esté hecho
    pana_session->server_ctx.OPTIMIZED_INIT = UNSET;
    // dependiendo de lo que queramos
    pana_session->NONCE_SENT = UNSET;
    pana_session->RTX_COUNTER = 0;
    rtxTimerStop();

    //-------------------------------------------------------------------------------
    table[INITIAL][PCI_PAA_INIT_PANA] = pciPaaInitPana;
    //-------------------------------------------------------------------------------

    table[INITIAL][PAN_HANDLING] = panHandling;
    //-------------------------------------------------------------------------------

    table[WAIT_EAP_MSG][RECEIVING_EAP_REQUEST] = receivingEapRequest;
    //-------------------------------------------------------------------------------

    table[WAIT_EAP_MSG][RX_EAP_SUCCESS_FAILURE] = rxEapSuccessFailure;
    //-------------------------------------------------------------------------------

    table[WAIT_EAP_MSG][RX_EAP_TIMEOUT_INVALID_MSG] = rxEapTimeoutInvalidMsg;
    //-------------------------------------------------------------------------------

    table[WAIT_SUCC_PAN][PAN_PROCESSING] = panProcessingStateWaitSuccPan;
    //-------------------------------------------------------------------------------

    table[WAIT_FAIL_PAN][PAN_PROCESSING] = panProcessingStateWaitFailPan;
    //-------------------------------------------------------------------------------

    table[OPEN][REAUTH_INIT_PAC] = reauthInitPacStateOpen;
    //-------------------------------------------------------------------------------

    table[OPEN][REAUTH_INIT_PAA] = reauthInitPaa;
    //-------------------------------------------------------------------------------

    table[OPEN][LIVENESS_TEST_EX_INIT_PAA] = livenessTestExInitPaa;
    //-------------------------------------------------------------------------------

    table[OPEN][SESSION_TERM_INIT_PAA] = sessionTermInitPaa;
    //-------------------------------------------------------------------------------

    table[OPEN][SESSION_TERM_INIT_PAC] = sessionTermInitPacStateOpen;
    //-------------------------------------------------------------------------------

    table[WAIT_PNA_PING][PNA_PROCESSING] = pnaProcessing;
    //-------------------------------------------------------------------------------

    table[WAIT_PNA_PING][REAUTH_INIT_PAC] = reauthInitPacStateWaitPnaPing;
    //-------------------------------------------------------------------------------

    table[WAIT_PNA_PING][SESSION_TERM_INIT_PAC] = sessionTermInitPacStateWaitPnaPing;
    //-------------------------------------------------------------------------------

    table[WAIT_PAN_OR_PAR][PAR_PROCESSING] = parProcessing;
    //-------------------------------------------------------------------------------

    table[WAIT_PAN_OR_PAR][PASS_EAP_RESP_TO_EAP_AUTH] = passEapRespToEapAuth;
    //-------------------------------------------------------------------------------

    table[WAIT_PAN_OR_PAR][PAN_WITHOUT_EAP_RESPONSE] = panWithoutEapResponse;
    //-------------------------------------------------------------------------------

    table[WAIT_PAN_OR_PAR][EAP_RETRANSMISSION] = eapRetransmission;
    //-------------------------------------------------------------------------------

    table[WAIT_PAN_OR_PAR][EAP_AUTH_TIMEOUT_FAILURE] = eapAuthTimeoutFailure;
    //-------------------------------------------------------------------------------
    table[SESS_TERM][PTA_PROCESSING] = ptaProcessing;
    //-------------------------------------------------------------------------------
    //Catch all event on closed state
    table[CLOSED][PCI_PAA_INIT_PANA] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PAN_HANDLING] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][RECEIVING_EAP_REQUEST] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][RX_EAP_SUCCESS_FAILURE] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][RX_EAP_TIMEOUT_INVALID_MSG] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PAN_PROCESSING] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][REAUTH_INIT_PAC] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][REAUTH_INIT_PAA] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][LIVENESS_TEST_EX_INIT_PAA] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][SESSION_TERM_INIT_PAA] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][SESSION_TERM_INIT_PAC] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PNA_PROCESSING] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PAR_PROCESSING] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PASS_EAP_RESP_TO_EAP_AUTH] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PAN_WITHOUT_EAP_RESPONSE] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][EAP_RETRANSMISSION] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][EAP_AUTH_TIMEOUT_FAILURE] = allEventClosedState;
    //-------------------------------------------------------------------------------

    table[CLOSED][PTA_PROCESSING] = allEventClosedState;
    //-------------------------------------------------------------------------------
}

// Implementation of the functions that check the exit conditions

int pciPaaInitPana() {
	
    if ((LMTYPE == PCI_MSG) || (current_session->server_ctx.PAC_FOUND)) {
        if (current_session->server_ctx.OPTIMIZED_INIT == SET) {
            eapRestart();
            //FIXME: FAILED_SESS_TIMEOUT está en el rfc pero en la parte del cliente!!!!
            //sessionTimerReStart(FAILED_SESS_TIMEOUT);

        } else {
			XFREE(current_session->retr_msg);
            if (generatePanaSa()) {
				if (IP_VERSION==4){
					current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_PRF | F_INTEG, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));

					//The initial PAR must be saved
					current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
					memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
					
					if (current_session->pre_dst_addr.sin_family == AF_INET) {
						current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
					}
				}
				else if (IP_VERSION==6){
					current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_PRF | F_INTEG, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));

					//The initial PAR must be saved
					current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
					memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
					
					if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
						current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
					}
				}
				
            } else {
				if (IP_VERSION==4){
					current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
					XFREE(current_session->I_PAR);
					
					//The initial PAR must be saved
					current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
					memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
			
					if (current_session->pre_dst_addr.sin_family == AF_INET) {
						current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
					}
				}
				else if (IP_VERSION==6){
					current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
					
					//The initial PAR must be saved
					current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
					memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
					
					if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
						current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
					}
				}
            }
            
        }
        return INITIAL;
    } else if (eap_auth_get_eapReq(&(current_session->eap_ctx)) == TRUE) {
        struct wpabuf * packet = eap_auth_get_eapReqData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = packet;
		XFREE(current_session->retr_msg);
        if (generatePanaSa()) {
			if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_PRF | F_INTEG , IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				
				//The initial PAR message must be saved.
				XFREE(current_session->I_PAR);
				current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
				memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
		
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_PRF | F_INTEG , IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));

				//The initial PAR message must be saved.
				XFREE(current_session->I_PAR);
				current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
				memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));

				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        } else {
			if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));

				//The initial PAR message must be saved.
				XFREE(current_session->I_PAR);
				current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
				memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
				
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6) {
				current_session->retr_msg = transmissionMessage("PAR", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));

				//The initial PAR message must be saved.
				XFREE(current_session->I_PAR);
				current_session->I_PAR = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
				memcpy(current_session->I_PAR,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
				
				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        }
        
        eap_auth_set_eapReq(&(current_session->eap_ctx), FALSE);
        rtxTimerStart();
        return INITIAL;
    } else return ERROR;
}

int panHandling() {
    bool rc; //Result code	
    rc = (LMTYPE == PAUTH_MSG) && !(LMFLAGS & R_FLAG) && (LMFLAGS & S_FLAG);
    rc = rc && ((current_session->server_ctx.OPTIMIZED_INIT == UNSET) || (existAvp(current_session->LAST_MESSAGE, F_EAPP)));

    if (rc) {
        if (existAvp(current_session->LAST_MESSAGE, F_EAPP)) {
            txEAP();
        } else {
            eapRestart();
            //FIXME: FAILED_SESS_TIMEOUT está en el rfc pero en la parte del cliente!!!!
            //sessionTimerReStart(FAILED_SESS_TIMEOUT);
        }
        return WAIT_EAP_MSG;
    } else if ((LMTYPE == PAUTH_MSG) && !(LMFLAGS & R_FLAG) && (LMFLAGS & S_FLAG) && ((current_session->server_ctx.OPTIMIZED_INIT == SET) && !existAvp(current_session->LAST_MESSAGE, F_EAPP))) {
        return WAIT_PAN_OR_PAR;
    } else return ERROR;
}

int receivingEapRequest() {
    if (eap_auth_get_eapReq(&(current_session->eap_ctx)) == TRUE) {
		pana_debug("EAP_REQ found");
        struct wpabuf * packet = eap_auth_get_eapReqData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = packet;
        XFREE(current_session->retr_msg);
		
        if (current_session->NONCE_SENT == UNSET) {
            //The nonce value must be saved
            if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, F_NONCE | F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				//Save the PAA nonce message before it is relayed (just in case).
				int size = ntohs(((pana*)(current_session->retr_msg))->msg_length);
				current_session->PAA_nonce = XMALLOC(char,size);
				memcpy(current_session->PAA_nonce,current_session->retr_msg,size);
				current_session->NONCE_SENT = SET;
				
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, F_NONCE | F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
				//Save the PAA nonce message before it is relayed (just in case).
				int size = ntohs(((pana*)(current_session->retr_msg))->msg_length);
				current_session->PAA_nonce = XMALLOC(char,size);
				memcpy(current_session->PAA_nonce,current_session->retr_msg,size);
				current_session->NONCE_SENT = SET;

				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
			
        } else {
			if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        }
        rtxTimerStart();
        //eapReq is set to false
        eap_auth_set_eapReq(&(current_session->eap_ctx), FALSE);
        return WAIT_PAN_OR_PAR;
    } else return ERROR;
}

int rxEapSuccessFailure() {

    if (eap_auth_get_eapFail(&(current_session->eap_ctx)) == TRUE) {
		pana_debug("EAP_FAILURE = TRUE");
        current_session->avp_data[RESULTCODE_AVP] = (void *) PANA_AUTHENTICATION_REJECTED;
        //The C flag is added
        struct wpabuf * eap_packet = eap_auth_get_eapReqData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = eap_packet;
        XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_RES, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_RES, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        rtxTimerStart();
        sessionTimerStop();
        eap_auth_set_eapFail(&(current_session->eap_ctx), FALSE);
        return WAIT_FAIL_PAN;
    } else if (eap_auth_get_eapSuccess(&(current_session->eap_ctx)) == TRUE && authorize()) {
		pana_debug("EAP_SUCCESS && Authorize()");
        current_session->avp_data[RESULTCODE_AVP] = (void*) PANA_SUCCESS;
        current_session->avp_data[SESSIONLIFETIME_AVP] = (void*) LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG;
        struct wpabuf * eap_packet = eap_auth_get_eapReqData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = eap_packet; //EAP packet is stored in the parameter
        XFREE(current_session->retr_msg);
		
        //The C flag is added
        if (newKeyAvailable()) {
			pana_debug("Function rxEapSuccessFailure, newKeyAvailable");
            //Key-Id stored in the parameter
            current_session->avp_data[KEYID_AVP] = current_session->key_id;
            if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_KEYID | F_RES | F_SESS, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_KEYID | F_RES | F_SESS, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        } else {
			pana_debug("Function rxEapSuccessFailure, !newKeyAvailable");
			if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_RES | F_SESS, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_RES | F_SESS, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        }
        eap_auth_set_eapSuccess(&(current_session->eap_ctx), FALSE);
        rtxTimerStart();
        return WAIT_SUCC_PAN;
    } else if (eap_auth_get_eapSuccess(&(current_session->eap_ctx)) == TRUE && !authorize()) {
		pana_debug("EAP_SUCCESS && !Authorize()");
        current_session->avp_data[RESULTCODE_AVP] = (void*) PANA_AUTHORIZATION_REJECTED;
        struct wpabuf * eap_packet = eap_auth_get_eapReqData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = eap_packet;
        XFREE(current_session->retr_msg);
		
        if (newKeyAvailable()) {
            //The C flag is added
            //Key-Id stored in the parameter
            current_session->avp_data[KEYID_AVP] = current_session->key_id;
            if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_KEYID | F_RES, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_KEYID | F_RES, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        } else {
			if (IP_VERSION==4){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_RES, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
				if (current_session->pre_dst_addr.sin_family == AF_INET) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
				}
			}
			else if (IP_VERSION==6){
				current_session->retr_msg = transmissionMessage("PAR", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP | F_RES, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
				if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
					current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
				}
			}
        }
        eap_auth_set_eapSuccess(&(current_session->eap_ctx), FALSE);
        rtxTimerStart();
        return WAIT_FAIL_PAN;
    } else
        return ERROR;
}

int rxEapTimeoutInvalidMsg() {

    if (eap_auth_get_eapTimeout(&(current_session->eap_ctx)) == TRUE
            /*|| current_session->server_ctx.EAP_DISCARD*/) { //FIXME: Que pasa con get_eapDiscard?
        sessionTimerStop();
        disconnect();
        eap_auth_set_eapTimeout(&(current_session->eap_ctx), FALSE);
        return CLOSED;
    } else return ERROR;
}

int panProcessingStateWaitSuccPan() {
    if ((LMTYPE == PAUTH_MSG) && !(LMFLAGS & R_FLAG) && (LMFLAGS & C_FLAG)) {
        rtxTimerStop();
        sessionTimerReStart(current_session->LIFETIME_SESS_TIMEOUT);
        return OPEN;
    } else return ERROR;
}

int panProcessingStateWaitFailPan() {
    if ((LMTYPE == PAUTH_MSG) && !(LMFLAGS & R_FLAG) && (LMFLAGS & C_FLAG)) {
        rtxTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

int reauthInitPacStateOpen() {
    if ((LMTYPE == PNOTIF_MSG) && (LMFLAGS & R_FLAG) && (LMFLAGS & A_FLAG)) {
        current_session->NONCE_SENT = UNSET;
        eapRestart();
        //The A flag is added
        XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PNA", A_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PNA", A_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
			/*#ifdef AESCRYPTO
			// Hack to operate with small nodes such as z1, jennic.
			// In those scenarios, PNA and next message (EAP Request Identity) cannot be sent simultaneously
			pana_warning("Sleeping node because of constrained working mode");
			waitusec(100000);
			//usleep(500000);
			#endif*/
		}
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int reauthInitPaa() {
    if ((current_session->REAUTH) || (current_session->server_ctx.REAUTH_TIMEOUT)) {
        current_session->NONCE_SENT = UNSET;
        eapRestart();
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int livenessTestExInitPaa() {
    if (current_session->PANA_PING) {
		XFREE(current_session->retr_msg);
		
        //The P flag is added
        if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PNR", P_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PNR", P_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        rtxTimerStart();
        current_session->PANA_PING = FALSE;
        return WAIT_PNA_PING;
    } else return ERROR;
}

int sessionTermInitPaa() {
    if (current_session->TERMINATE) {
        current_session->avp_data[TERMINATIONCAUSE_AVP] = (void*)ADMINISTRATIVE; //FIXME: Esto también puede ser SESSION_TIMEOUT
        //FIXME: ver cual poner en cada caso
        XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PTR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PTR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        sessionTimerStop();
        rtxTimerStart();
        return SESS_TERM;
    } else return ERROR;
}

int sessionTermInitPacStateOpen() {
    if ((LMTYPE == PTERM_MSG) && (LMFLAGS & R_FLAG)) {
		XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        sessionTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

int pnaProcessing() {
    if ((LMTYPE == PNOTIF_MSG) && !(LMFLAGS & R_FLAG) && (LMFLAGS & P_FLAG)) {
        rtxTimerStop();
        return OPEN;
    } else return ERROR;
}

int reauthInitPacStateWaitPnaPing() {
    if ((LMTYPE == PNOTIF_MSG) && (LMFLAGS & R_FLAG) && (LMFLAGS & A_FLAG)) {
        rtxTimerStop();
        current_session->NONCE_SENT = UNSET;
        eapRestart();
        XFREE(current_session->retr_msg);
		
        //The A flag is added
        if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PNA", A_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PNA", A_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int sessionTermInitPacStateWaitPnaPing() {
    if ((LMTYPE == PTERM_MSG) && (LMFLAGS & R_FLAG)){
        rtxTimerStop();
        XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        sessionTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

int parProcessing() {
    if ((LMTYPE == PAUTH_MSG) && (LMFLAGS & R_FLAG)){
        txEAP();
        rtxTimerStop();
        XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int passEapRespToEapAuth() {
    if ((LMTYPE == PAUTH_MSG) && !(LMFLAGS & R_FLAG) && (existAvp(current_session->LAST_MESSAGE, F_EAPP))) { 
        txEAP();
        rtxTimerStop();
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int panWithoutEapResponse() {
    if (( LMTYPE == PAUTH_MSG && !(LMFLAGS & R_FLAG)) && (!existAvp(current_session->LAST_MESSAGE, F_EAPP))) {
        rtxTimerStop();
        return WAIT_PAN_OR_PAR;
    } else return ERROR;
}

int eapRetransmission() {
    if (eap_auth_get_eapReq(&(current_session->eap_ctx)) == TRUE) {
        rtxTimerStop();

        struct wpabuf * packet = eap_auth_get_eapReqData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = packet;
        XFREE(current_session->retr_msg);

		if (IP_VERSION==4){
			current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			if (current_session->pre_dst_addr.sin_family == AF_INET) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
		}
		else if (IP_VERSION==6){
			current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, F_EAPP, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family==AF_INET6));
			if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), current_session->retr_msg, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
		}
        eap_auth_set_eapReq(&(current_session->eap_ctx), FALSE);
        rtxTimerStart();
        return WAIT_PAN_OR_PAR;
    } else return ERROR;
}

int eapAuthTimeoutFailure() {
    if (eap_auth_get_eapFail(&(current_session->eap_ctx)) == TRUE
            || eap_auth_get_eapTimeout(&(current_session->eap_ctx)) == TRUE
            /*|| current_session->server_ctx.EAP_DISCARD*/) { //FIXME: Que pasa con el DISCARD?Pacovi: está ya solucionado?
        rtxTimerStop();
        sessionTimerStop();
        disconnect();
        eap_auth_set_eapFail(&(current_session->eap_ctx), FALSE);
        return CLOSED;
    } else return ERROR;
}

int ptaProcessing() {
    if (LMTYPE == PTERM_MSG && !(LMFLAGS & R_FLAG)) {
        rtxTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

// Procedures
int newKeyAvailable() {
	pana_debug("newKeyAvailable() function");
	int eapKeyAvailable = FALSE;
	eapKeyAvailable = eap_auth_get_eapKeyAvailable(&(current_session->eap_ctx));
	
	//If the state machine already has a PANA_AUTH_KEY, it returns FALSE.
	if (current_session->avp_data[AUTH_AVP] != NULL &&
		eapKeyAvailable == FALSE) {
		return FALSE;
	}
	//If the state machine does not have a PANA_AUTH_KEY
	else{
	//Tries to retrieve a Master Session Key (MSK) from the EAP entity
		if (eapKeyAvailable == TRUE) {
			pana_debug("EAP lower-layer Key Available");
			unsigned int key_len;
			#ifdef ISCLIENT
			u8* key = eap_peer_get_eapKeyData(&(current_session->eap_ctx), &key_len);
			#endif
			#ifdef ISSERVER
			u8* key = eap_auth_get_eapKeyData(&(current_session->eap_ctx), &key_len);
			#endif
			//The key and its length must be copied into the pana context
			pana_ctx * session = current_session;
			session->key_len = key_len;
			
			XFREE(session->msk_key);
			
			session->msk_key = XCALLOC(u8, key_len);
			memcpy(session->msk_key, key, key_len);
/*
#ifdef DEBUG
			//Prints the EAP MSK key for debugging purposes
			unsigned int i;
			for (i = 0; i < key_len; i++)
				fprintf(stderr,"%02x", key[i]);
			fprintf(stderr,"\n");
#endif*/
			//If an MSK is retrieved, it computes a PANA_AUTH_KEY from
			//the MSK and returns TRUE
			
			//First, the Key-Id of the new MSK is generated
			//by increasing the global key_id.
			XFREE(session->key_id);
			session->key_id = XMALLOC(char,session->key_id_length);
			
			increase_one(session->server_ctx.global_key_id, session->key_id_length);
			memcpy(session->key_id, session->server_ctx.global_key_id, session->key_id_length);
						
			//Afterwards we generate the PANA_AUTH_KEY
			u8 * new_auth_key = NULL;
			new_auth_key = generateAUTH(current_session);
			if(new_auth_key != NULL){
				XFREE(current_session->avp_data[AUTH_AVP]);
				current_session->avp_data[AUTH_AVP] = new_auth_key;
			}
			//If !=NULL the key generation was successful
			return current_session->avp_data[AUTH_AVP]!=NULL;
		}
		else //If an MSK isn't retrieved
			return FALSE;
	}
}
