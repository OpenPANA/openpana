/**
 * @file statemachine.c
 * @brief  State machine's common functions implementation.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2011.
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

#include "statemachine.h"
#include "session.h"
#include "../panamessages.h"
#include "../panautils.h"
#include "../prf_plus.h"
#include "../lalarm.h"

/** Reqs for getrusage function, maybe included somewhere else (performance test)*/
#include <sys/time.h>
#include <sys/resource.h>
/** end performance includes*/

// Init the state machine table's positions
void initTable() {
    table [INITIAL][RETRANSMISSION] = retransmission;

    table [WAIT_PNA_PING][RETRANSMISSION] = retransmission;

    table [WAIT_PAA][RETRANSMISSION] = retransmission;

    table [WAIT_EAP_MSG][RETRANSMISSION] = retransmission;

    table [WAIT_EAP_RESULT][RETRANSMISSION] = retransmission;

    table [WAIT_EAP_RESULT_CLOSE][RETRANSMISSION] = retransmission;

    table [OPEN][RETRANSMISSION] = retransmission;

    table [WAIT_PNA_REAUTH][RETRANSMISSION] = retransmission;

    table [SESS_TERM][RETRANSMISSION] = retransmission;

    table [WAIT_PAN_OR_PAR][RETRANSMISSION] = retransmission;

    table [WAIT_FAIL_PAN][RETRANSMISSION] = retransmission;

    table [WAIT_SUCC_PAN][RETRANSMISSION] = retransmission;

    table [WAIT_PAN_OR_PAR][RETRANSMISSION] = retransmission;
    //-----------------------------------------------------------------------//

    table [INITIAL][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_PNA_PING][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_PAA][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_EAP_MSG][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_EAP_RESULT][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_EAP_RESULT_CLOSE][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [OPEN][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_PNA_REAUTH][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [SESS_TERM][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_PAN_OR_PAR][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_FAIL_PAN][REACH_MAX_NUM_RT] = reachMaxNumRt;

    table [WAIT_SUCC_PAN][REACH_MAX_NUM_RT] = reachMaxNumRt;
    //------------------------------------------------------------------------//

    // This event doesn't work with INITIAL state
    table [WAIT_PNA_PING][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_PAA][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_EAP_MSG][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_EAP_RESULT][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_EAP_RESULT_CLOSE][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [OPEN][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_PNA_REAUTH][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [SESS_TERM][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_PAN_OR_PAR][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_FAIL_PAN][LIVENESS_TEST_PEER] = livenessTestPeer;

    table [WAIT_SUCC_PAN][LIVENESS_TEST_PEER] = livenessTestPeer;
    //------------------------------------------------------------------------//

    // This event doesn't work with WAIT_PNA_PING state
    table [INITIAL][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_PAA][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_EAP_MSG][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_EAP_RESULT][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_EAP_RESULT_CLOSE][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [OPEN][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_PNA_REAUTH][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [SESS_TERM][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_PAN_OR_PAR][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_FAIL_PAN][LIVENESS_TEST_RESPONSE] = livenessTestResponse;

    table [WAIT_SUCC_PAN][LIVENESS_TEST_RESPONSE] = livenessTestResponse;
    //-----------------------------------------------------------------------//
    //Catch all event on closed state
    table [CLOSED][RETRANSMISSION] = allEventClosedState;

    table [CLOSED][REACH_MAX_NUM_RT] = allEventClosedState;

    table [CLOSED][LIVENESS_TEST_PEER] = allEventClosedState;

    table [CLOSED][LIVENESS_TEST_RESPONSE] = allEventClosedState;

    //-----------------------------------------------------------------------//
}

// Do the transitions between two states

int transition(pana_ctx *pana_session) {
    // If there isn't a pana_session available or the state isn't a valid number
    if (pana_session == NULL || pana_session->CURRENT_STATE > NUM_STATES) {
        return ERROR;
    }

    current_session = pana_session;
     
    pana_debug("Trying a transition..");
    pana_debug("Session ID: %d, current state: %s", current_session->session_id, state_name[current_session->CURRENT_STATE + 1]);

    int i; // Events' iterator
    int rs = ERROR; // result state
    for (i = 0; i < NUM_EVENTS && rs == ERROR; i++) {
        if (table[current_session->CURRENT_STATE][i] != NULL) {
            rs = table[current_session->CURRENT_STATE][i]();
        }
    }

	if (rs == ERROR)
		return ERROR;
		
	printf("PANA: Entering state: %s (Session ID: %d).\n", state_name[rs + 1], current_session->session_id);
	if (rs != NO_CHANGE) {
		pana_session->CURRENT_STATE = rs;
    }
    
    return 0;
}

// Common Procedures

void disconnect() {
	pana_debug("disconnect function");
#ifdef ISCLIENT

	//FIXME: Hay que ponerlo? creo que no hace falta
	//XFREE(current_session->LAST_MESSAGE);
	pana_debug("freeing key_id");
	XFREE(current_session->key_id);
	pana_debug("freeing msk_key");
	XFREE(current_session->msk_key);
	pana_debug("freeing I_PAR");
	XFREE(current_session->I_PAR);
	pana_debug("freeing I_PAN");
	XFREE(current_session->I_PAN);
	pana_debug("freeing PAA_Nonce");
	XFREE(current_session->PAA_nonce);
	pana_debug("freeing PaC_Nonce");
	XFREE(current_session->PaC_nonce);

    printf("PANA: Client disconnected.\n");
    exit(EXIT_SUCCESS);
    //FIXME: hay que liberar esto? XFREE(current_session->avp_data);
#endif

#ifdef ISSERVER
    //FIXME: hay que liberar esto? XFREE(current_session);
#endif
}

int authorize() {
    //Tenerlo en cuenta a la hora de implementar el método, despues ver
    //si sería conveniente eliminarlo de la documentación generada o no
    /* It is assumed that authorize() procedure of PaC state machine
     * always returns TRUE. In the case that a non-key-generating EAP
     * method is used but a PANA SA is required after successful
     * authentication (generate_pana_sa() returns TRUE), authorize()
     * procedure must return FALSE.  */
	 pana_debug("authorize function"); //TODO: Falta la implementación

     #ifdef ISCLIENT// It is assumed that authorize() procedure of PaC 
     return TRUE;	// state machine always returns TRUE.
     #else // PAA behaviour
	 return 1; 
     #endif
    
}

void retransmit() {
	pana_debug("Message to retransmit:");
    debug_msg((pana*)current_session->retr_msg);

    current_session->RTX_TIMEOUT = 0;
    int numbytes;
    if (IP_VERSION==4){
		#ifdef ISSERVER
		if (current_session->pre_dst_addr.sin_family==AF_INET) {
			numbytes = sendPana(current_session->pre_dst_addr, current_session->retr_msg, current_session->socket);
			if (0 >= numbytes) {
				pana_fatal("sendPana in rentransmit");
			}
		}
		else{
			numbytes = sendPana(current_session->eap_ll_dst_addr, current_session->retr_msg, current_session->socket);
			if (0 >= numbytes) {
				pana_fatal("sendPana in rentransmit");
			}
		}
		#endif

		#ifdef ISCLIENT
		numbytes = sendPana(current_session->eap_ll_dst_addr, current_session->retr_msg, current_session->socket);
		if (0 >= numbytes) {
			pana_fatal("sendPana in rentransmit");
		}
		#endif
		
	}

	else if (IP_VERSION==6) {
		#ifdef ISSERVER
		if (current_session->pre_dst_addr6.sin6_family==AF_INET6) {
			numbytes = sendPana6(current_session->pre_dst_addr6, current_session->retr_msg, current_session->socket);
			if (0 >= numbytes) {
				pana_fatal("sendPana6 in rentransmit");
			}
		}
		else {
			numbytes = sendPana6(current_session->eap_ll_dst_addr6, current_session->retr_msg, current_session->socket);
			if (0 >= numbytes) {
				pana_fatal("sendPana6 in rentransmit");
			}
		}
		#endif

		#ifdef ISCLIENT
		numbytes = sendPana6(current_session->eap_ll_dst_addr6, current_session->retr_msg, current_session->socket);
		if (0 >= numbytes) {
			pana_fatal("sendPana6 in rentransmit");
		}
		#endif
	}
    current_session->RTX_COUNTER += 1;
    current_session->RT = 2 * current_session->RT + current_session->RAND * current_session->RT;
    if (current_session->MRT /*MRT != 0*/ && current_session->RT > current_session->MRT){//See rfc 5191 page 34
            current_session->RT = current_session->MRT + current_session->RAND * current_session->MRT;
    }

    if (current_session->MRD /*MRD != 0*/ && current_session->RT > current_session->MRD){
            current_session->RT = 0;
    }
    add_alarma(current_session->list_of_alarms, current_session, current_session->RT, RETR_ALARM);

}

void rtxTimerStart() {
	pana_debug("rtxTimerStart function");

    current_session->RTX_COUNTER = 0; // Reset retransmission's counter
    //current_session->RTX_MAX_NUM; //This value is updated in the session's initialization

    current_session->RT = current_session->IRT + current_session->RAND * current_session->IRT;

    add_alarma(current_session->list_of_alarms, current_session, current_session->RT, RETR_ALARM);

}

void rtxTimerStop() {
	pana_debug("rtxTimerStop  function");

    if (current_session == NULL) {
		pana_debug("There isn't any session associated");
        return;
    }
    pana_ctx * session = get_alarm_session(current_session->list_of_alarms, current_session->session_id, RETR_ALARM);
}

void sessionTimerReStart(int timeout) {
	pana_debug("sessionTimerReStart function. Timeout: %d", timeout); 
	//Get the alarm of this session
    pana_ctx * session = get_alarm_session(current_session->list_of_alarms, current_session->session_id, SESS_ALARM);
	
	//Add the alarm with the new expiration time
	add_alarma(current_session->list_of_alarms, current_session, timeout, SESS_ALARM);
}

void eapRestart() {
	pana_debug("eapRestart function");

	//It is necesary reset the session's variables used to generate the pana auth key
	// due to the eap conversation will be reinited
	
	//FIXME: Hay que liberar la msk_key?
	current_session->msk_key = NULL;
	current_session->key_len = 0;
	//FIXME: Hay que liberar la estructura current_session->avp_data?

	/*if (current_session->avp_data!=NULL){
		//XFREE(current_session->avp_data[AUTH_AVP]);
		current_session->avp_data[AUTH_AVP] = NULL;
	}*/
	
    //The RESET value of EAPsession must be set to true
#ifdef ISCLIENT //only for PANA clients
    eap_peer_set_eapRestart(&(current_session->eap_ctx), TRUE);
    eap_peer_step(&(current_session->eap_ctx));
#endif

#ifdef ISSERVER //only for PANA servers
    eap_auth_set_eapRestart(&(current_session->eap_ctx), TRUE);
    eap_auth_step(&(current_session->eap_ctx));
#endif
	pana_debug("eapReStart: EAP has been properly restarted.\n");
}

void txEAP() {
        struct rusage usage;//To measure cpu usage
	struct timeval ti, tf;
	double timestamp;


        //Get usage measurement for the initial time
        getrusage(RUSAGE_SELF, &usage);
        ti = usage.ru_utime;
	
	pana_debug("txEAP function");
    //Get the EAP_Payload Avp

    avp_pana * elmnt = (avp_pana *) getAvp(current_session->LAST_MESSAGE, EAPPAYLOAD_AVP);
    if (elmnt==NULL){
		pana_warning("txEAP: There isn't EAP Payload AVP");
		return;
	}

    //The Request value of EAPsession must be set to true
#ifdef ISCLIENT //only for PANA clients
    eap_peer_set_eapReq(&(current_session->eap_ctx), TRUE);
    const u8 * elmntvalue = (const u8 *) ((char*)elmnt)+sizeof(avp_pana);
    eap_peer_set_eapReqData(&(current_session->eap_ctx), elmntvalue, ntohs(elmnt->length));
    eap_peer_step(&(current_session->eap_ctx));
#endif

	//The Response value of EAPsession must be set to true
#ifdef ISSERVER //only for PANA servers
    eap_auth_set_eapResp(&(current_session->eap_ctx), TRUE);
    const u8 * elmntvalue = (const u8 *) ((char*)elmnt)+sizeof(avp_pana);
    eap_auth_set_eapRespData(&(current_session->eap_ctx), elmntvalue, ntohs(elmnt->length));
    eap_auth_step(&(current_session->eap_ctx));
    
    add_alarma(current_session->list_of_alarms, current_session, 1, RETR_AAA); //FIXME: El tiempo de retransmsiones
																		       // de eap no se cual es
#endif
	pana_debug("Finished txEAP function\n");

        //Get usage for the final time
	getrusage(RUSAGE_SELF, &usage);
        tf = usage.ru_utime;

	timestamp= (tf.tv_sec - ti.tv_sec)*1000 + (tf.tv_usec - ti.tv_usec)/1000.0;
	fprintf(stderr, "%f ", timestamp);
}

void sessionTimerStop() {

	pana_debug("sessionTimerStop function");
	//Get the alarm of this session
	pana_ctx * session = get_alarm_session(current_session->list_of_alarms, current_session->session_id,SESS_ALARM);
	pana_debug("sessionTimerStop finished");
}

int generatePanaSa() { // See RFC 5609 Page 8
	pana_debug("generatePanaSa function");
    //TODO: Falta la implementación
    //If the EAP method does not generate a key (MSK)
    // return FALSE;
    
    #ifdef ISCLIENT
	/* Check if the PaC can match the PRF and Integrity algorithm AVPs
	 * advertised by the PAA in PAR[S] message */
	 // If the algorithms cannot be matched, return false.
    #endif
    
    #ifdef ISSERVER
    /* Indicate whether a PRF and Integrity algorithm AVPs will be sent
     * in the PAR[S]. If a non-generating algorithm is used, return false.
     * */
    #endif
    
    return TRUE;
}

int keyAvailable() {
		//Variable to store if there's an EAP key available
	int eapKeyAvailable = FALSE; 
	//Check if there's an EAP key available.
	#ifdef ISCLIENT
	eapKeyAvailable = eap_peer_get_eapKeyAvailable(&(current_session->eap_ctx));
	#endif
	#ifdef ISSERVER
	eapKeyAvailable = eap_auth_get_eapKeyAvailable(&(current_session->eap_ctx));
	#endif
	
	if(current_session->avp_data[AUTH_AVP] == NULL){
		pana_debug("KeyAvailable: AUTH KEY equals NULL");
	}
	
	//If the state machine already has a PANA_AUTH_KEY, it returns TRUE.
	if(current_session->avp_data[AUTH_AVP] != NULL && eapKeyAvailable == FALSE){
		return TRUE;
	}
	//If the state machine does not have a PANA_AUTH_KEY
	else{
	//Tries to retrieve a Master Session Key (MSK) from the EAP entity
		if (eapKeyAvailable == TRUE) {
			pana_debug("EAP lower-layer Key Available");
			unsigned int key_len;
			u8* key = NULL;
			#ifdef ISCLIENT
			key = eap_peer_get_eapKeyData(&(current_session->eap_ctx), &key_len);
			#endif
			#ifdef ISSERVER
			key = eap_auth_get_eapKeyData(&(current_session->eap_ctx), &key_len);
			#endif
			//The key and its length must be copied into the pana context
			pana_ctx * session = current_session;
			session->key_len = key_len;
			if(session->msk_key != NULL){
				XFREE(session->msk_key);
				session->msk_key = NULL;
			}
			session->msk_key = XCALLOC(u8, key_len);
			memcpy(session->msk_key, key, key_len);

			//We generate the PANA_AUTH_KEY
			u8 * new_auth_key = NULL;
			new_auth_key = generateAUTH(current_session);
			if(new_auth_key != NULL){
				XFREE(current_session->avp_data[AUTH_AVP]);
				current_session->avp_data[AUTH_AVP] = new_auth_key;
			}
			else{
				pana_debug("KeyAvailable - Generated AUTH key is NULL!");
			}
			//If !=NULL the key generation was successful
			return current_session->avp_data[AUTH_AVP]!=NULL;
		}
		else //If an MSK isn't retrieved
			return FALSE;
	}
}

// Common functions

int retransmission() {
    if ((current_session->RTX_TIMEOUT && (current_session->RTX_COUNTER < current_session->RTX_MAX_NUM))) {
        retransmit();
        return NO_CHANGE;
    } else
        return ERROR;
}

int reachMaxNumRt() {
    if ((current_session->RTX_TIMEOUT && current_session->RTX_COUNTER >= current_session->RTX_MAX_NUM) || current_session->SESS_TIMEOUT) {
        disconnect();
        return CLOSED;
    } else
        return ERROR;
}

int livenessTestPeer() {
    pana_debug("livenessTestPeer");
    if ((LMTYPE == PNOTIF_MSG) && (LMFLAGS & R_FLAG) && (LMFLAGS & P_FLAG)) {
		char * unused;
		if (IP_VERSION==4){
			#ifdef ISCLIENT
				unused = transmissionMessage("PNA", P_FLAG, &(current_session->NEXT_INCOMING_REQUEST), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket,  FALSE);
			#endif
			
			#ifdef ISSERVER
			unused = transmissionMessage("PNA", P_FLAG, &(current_session->NEXT_INCOMING_REQUEST), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr.sin_family == AF_INET));
			
			if (current_session->pre_dst_addr.sin_family==AF_INET){
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr), unused, current_session->socket, &(current_session->eap_ll_dst_addr));
			}
			#endif

		}
		else if (IP_VERSION==6){
			#ifdef ISCLIENT
				unused = transmissionMessage("PNA", P_FLAG, &(current_session->NEXT_INCOMING_REQUEST), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, FALSE);
			#endif
			
			#ifdef ISSERVER
			unused = transmissionMessage("PNA", P_FLAG, &(current_session->NEXT_INCOMING_REQUEST), current_session->session_id, 0, IP_VERSION, &(current_session->eap_ll_dst_addr6), current_session->avp_data, current_session->socket, (current_session->pre_dst_addr6.sin6_family == AF_INET6));
			
			if (current_session->pre_dst_addr6.sin6_family == AF_INET6) {
				current_session->retr_msg = transmissionRelayedMessage(IP_VERSION, &(current_session->pre_dst_addr6), unused, current_session->socket, &(current_session->eap_ll_dst_addr6));
			}
			#endif
		}
        XFREE(unused);
        return NO_CHANGE;
    } else
        return ERROR;
}

int livenessTestResponse() {
    pana_debug("livenessTestResponse");
    if ((LMTYPE == PNOTIF_MSG) && !(LMFLAGS & R_FLAG) && (LMFLAGS & P_FLAG)) {
        return NO_CHANGE;
    }
    
    return ERROR;
}

int allEventClosedState() {
    return CLOSED;
}

