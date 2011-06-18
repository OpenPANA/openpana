/*
 *  statemachine.c
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "statemachine.h"
#include "session.h"
#include "../panamessages.h"
#include "../panautils.h"
#include "../prf_plus.h"
#include "../lalarm.h"

pana_ctx pana_session;
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
    // If there isn't a pana_session available
    if (pana_session == NULL) {
        return ERROR;
    }
    
    // If the state isn't a valid number
    if (pana_session->CURRENT_STATE > NUM_STATES) {
        return ERROR;
    }

    current_session = pana_session;
    //Array para mostrar los nombres de los estados
    char * state_name[] = {"NO CHANGE", "INITIAL", "WAIT_PNA_PING",
        "CLOSED", "WAIT_PAA", "WAIT_EAP_MSG",
        "WAIT_EAP_RESULT", "WAIT_EAP_RESULT_CLOSE",
        "OPEN", "WAIT_PNA_REAUTH", "SESS_TERM",
        "WAIT_PAN_OR_PAR", "WAIT_FAIL_PAN",
        "WAIT_SUCC_PAN"};
        
	#ifdef DEBUG
    fprintf(stderr, "DEBUG: Trying a transition...\n");
    fprintf(stderr, "DEBUG: Session ID: %d, current state: %s .\n", current_session->session_id, state_name[current_session->CURRENT_STATE + 1]);
    #endif

    int i; // Events' iterator
    int rs = ERROR; // result state
    for (i = 0; i < NUM_EVENTS && rs == ERROR; i++) {
        if (table[current_session->CURRENT_STATE][i] != NULL) {
            rs = table[current_session->CURRENT_STATE][i]();
        }
    }

    if (rs != ERROR) {
        printf("PANA: Entering state: %s (Session ID: %d).\n", state_name[rs + 1], current_session->session_id);
        if (rs != NO_CHANGE) {
            pana_session->CURRENT_STATE = rs;
        }
    } else {
        return ERROR;
    }

    return 0;

}

// Common Procedures

void none() {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Funcion none \n");
#endif
}

void disconnect() {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función disconnect \n");
#endif

	if(current_session->LAST_MESSAGE !=NULL){
		free(current_session->LAST_MESSAGE);
	}
	if(current_session->key_id !=NULL){
		free(current_session->key_id);
	}
    if(current_session->msk_key !=NULL){
		free(current_session->msk_key);
	}
    if(current_session->I_PAR !=NULL){
		free(current_session->I_PAR);
	}
    if(current_session->I_PAN !=NULL){
		free(current_session->I_PAN);
	}
    if(current_session->PAA_nonce !=NULL){
		free(current_session->PAA_nonce);
	}
    if(current_session->PaC_nonce !=NULL){
		free(current_session->PaC_nonce);
	}
	
#ifdef ISCLIENT
    printf("PANA: El cliente se desconecta\n");
    exit(0);
    //free(current_session->avp_data);
#endif

/*#ifdef ISSERVER
    free(current_session);
#endif*/
}

int authorize() {
    //Tenerlo en cuenta a la hora de implementar el método, despues ver
    //si sería conveniente eliminarlo de la documentación generada o no
    /* It is assumed that authorize() procedure of PaC state machine
     * always returns TRUE. In the case that a non-key-generating EAP
     * method is used but a PANA SA is required after successful
     * authentication (generate_pana_sa() returns TRUE), authorize()
     * procedure must return FALSE.  */
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función authorize \n"); //TODO: Falta la implementación
#endif

     #ifdef ISCLIENT// It is assumed that authorize() procedure of PaC 
     return TRUE;	// state machine always returns TRUE.
     #else // PAA behaviour
	 return 1; 
     #endif
    
}

void retransmit() {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función retransmit \n");
#endif

    current_session->RTX_TIMEOUT = 0;
    int numbytes;
    numbytes = sendPana(current_session->eap_ll_dst_addr, current_session->retr_msg, current_session->socket);
    if (0 >= numbytes) {
        fprintf(stderr, "ERROR: sendPana in rentransmit.\n");
        exit(1);
    }
    current_session->RTX_COUNTER += 1;
    current_session->RT = 2 * current_session->RT + current_session->RAND * current_session->RT;
    if (current_session->MRT != 0) {//See rfc 5191 page 34
        if (current_session->RT > current_session->MRT)
            current_session->RT = current_session->MRT + current_session->RAND * current_session->MRT;
    }

    if (current_session->MRD != 0) {
        if (current_session->RT > current_session->MRD)
            current_session->RT = 0;
    }
    add_alarma(current_session->list_of_alarms, current_session, current_session->RT, RETR_ALARM);

}

void rtxTimerStart() {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función rtxTimerStart \n");
#endif

    current_session->RTX_COUNTER = 0; // Reset retransmission's counter
    //current_session->RTX_MAX_NUM; //This value is updated in the session's initialization

    current_session->RT = current_session->IRT + current_session->RAND * current_session->IRT;

    add_alarma(current_session->list_of_alarms, current_session, current_session->RT, RETR_ALARM);

}

void rtxTimerStop() {
#ifdef DEBUG
    fprintf(stderr, "DEBUG: Función rtxTimerStop \n");
#endif

    if (current_session == NULL) {
#ifdef DEBUG
        fprintf(stderr, "DEBUG: No hay sesión asociada\n");
#endif
        return;
    }
    pana_ctx * session = get_alarm_session(current_session->list_of_alarms, current_session->session_id, RETR_ALARM);
	

}

void sessionTimerReStart(int timeout) {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función sessionTimerReStart. Parámetro: %d \n", timeout); 
#endif
	//Get the alarm of this session
    pana_ctx * session = get_alarm_session(current_session->list_of_alarms, current_session->session_id, SESS_ALARM);
	
	
	
	//Add the alarm with the new expiration time
	add_alarma(current_session->list_of_alarms, current_session, timeout, SESS_ALARM);
}

void eapRestart() {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función eapRestart\n");
#endif

	//It is necesary reset the session's variables used to generate the pana auth key
	// due to the eap conversation will be reinited
	
	if (current_session->msk_key != NULL) free(current_session->msk_key);
	current_session->msk_key = NULL;
	current_session->key_len = 0;
	/*if (current_session->avp_data!=NULL){
		free(current_session->avp_data[AUTH_AVP]);
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
#ifdef DEBUG
    fprintf(stderr, "DEBUG: eapReStart: La máquina EAP ha sido reiniciada correctamente.\n");
#endif

}

void txEAP() {
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función txEAP\n");
#endif
    //Get the EAP_Payload Avp

    avp * elmnt = getAvp(current_session->LAST_MESSAGE, EAPPAYLOAD_AVP);
    if (elmnt==NULL){
		printf("txEAP: No hay un eappayload avp\n");
		return;
	}

    //The Request value of EAPsession must be set to true
#ifdef ISCLIENT //only for PANA clients
    eap_peer_set_eapReq(&(current_session->eap_ctx), TRUE);
    const u8 * elmntvalue = (const u8 *) &(elmnt->value);
    eap_peer_set_eapReqData(&(current_session->eap_ctx), elmntvalue, ntohs(elmnt->avp_length));
    eap_peer_step(&(current_session->eap_ctx));
#endif

	//The Response value of EAPsession must be set to true
#ifdef ISSERVER //only for PANA servers
    eap_auth_set_eapResp(&(current_session->eap_ctx), TRUE);
    const u8 * elmntvalue = (const u8 *) &(elmnt->value);
    eap_auth_set_eapRespData(&(current_session->eap_ctx), elmntvalue, ntohs(elmnt->avp_length));
    eap_auth_step(&(current_session->eap_ctx));
    
    add_alarma(current_session->list_of_alarms, current_session, 1, RETR_AAA); //FIXME: El tiempo de retransmsiones
																		       // de eap no se cual es
#endif
#ifdef DEBUG
   fprintf(stderr,"DEBUG: Terminada función txEAP\n");
#endif
}

void sessionTimerStop() {

#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función sessionTimerStop\n"); 
#endif

	//Get the alarm of this session
	pana_ctx * session = get_alarm_session(current_session->list_of_alarms, current_session->session_id,SESS_ALARM);

	
	
#ifdef DEBUG
    fprintf(stderr, "DEBUG: sessionTimerStop: Función terminada correctamente\n"); 
#endif
}

int generatePanaSa() { // See RFC 5609 Page 8
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Función generatePanaSa\n");
    //FIXME: Falta la implementación
#endif
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
	
	
	#ifdef DEBUG
	if(current_session->avp_data[AUTH_AVP] == NULL)
		fprintf(stderr,"****** KeyAvailable: CLAVE NULA AUTH");
	#endif
	
	//If the state machine already has a PANA_AUTH_KEY, it returns TRUE.
	if(current_session->avp_data[AUTH_AVP] != NULL && eapKeyAvailable == FALSE){
		return TRUE;
	}
	//If the state machine does not have a PANA_AUTH_KEY
	else{
	//Tries to retrieve a Master Session Key (MSK) from the EAP entity
		if (eapKeyAvailable == TRUE) {
#ifdef DEBUG
			fprintf(stderr,"DEBUG: EAP lower-layer Key Available!!!\n");
#endif
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

			session->msk_key = calloc(1, key_len);
			if(session->msk_key == NULL){
				fprintf(stderr,"ERROR: Out of memory.\n");
				exit(1);
			}
			memcpy(session->msk_key, key, key_len);

#ifdef DEBUG
			//Prints the EAP MSK key for debugging purposes
			unsigned int i;
			for (i = 0; i < key_len; i++)
				fprintf(stderr,"%02x", key[i]);
			fprintf(stderr,"\n");
#endif
			//If an MSK is retrieved, it computes a PANA_AUTH_KEY from
			//the MSK and returns TRUE
			u8 * new_auth_key = NULL;
			new_auth_key = generateAUTH(current_session);
			if(new_auth_key != NULL){
				if(current_session->avp_data[AUTH_AVP] != NULL){
					free(current_session->avp_data[AUTH_AVP]);
				}
				current_session->avp_data[AUTH_AVP] = new_auth_key;
			}
			else{
				fprintf(stderr,"DEBUG: AUTH key generada en keyAvailable es NULA!");
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
    if ((current_session->PNR.receive) && (current_session->PNR.flags & P_FLAG)) {
        char * unused = transmissionMessage("PNA", P_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        free(unused);
        return NO_CHANGE;
    } else
        return ERROR;
}

int livenessTestResponse() {
    if ((current_session->PNA.receive) && (current_session->PNA.flags & P_FLAG)) {
        none();
        return NO_CHANGE;
    } else
        return ERROR;
}

int allEventClosedState() {
    none();
    return CLOSED;
}

