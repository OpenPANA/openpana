/**
 * @file pacmachine.c
 * @brief  Implementation of PaC's state machine specific functions.
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

#include "pacmachine.h"
#include "statemachine.h"
#include "../panamessages.h"
#include "session.h"
#include "../panautils.h"

void initPacTable() {
    initTable(); // Init the common state machine between pac and paa
    // Initialization Action
    // These actions are done in the session's initialization
    //pana_session->NONCE_SENT = UNSET;
    //pana_session->RTX_COUNTER = 0;
    rtxTimerStop();

    //-------------------------------------------------------------------------------
    table[INITIAL][PAC_INIT_HANDSHAKE] = pacInitHandshake;
    //-------------------------------------------------------------------------------

    table[INITIAL][PAA_INIT_HANDSHAKE] = paaInitHandshake;
    //--------------------------------------------------------------------------------

    table[WAIT_PAA][PANA_RESULT] = panaResult;
    //--------------------------------------------------------------------------------

    table[WAIT_PAA][PAR_PAN_EXCHANGE] = parPanExchange;
    //---------------------------------------------------------------------------------

    table[WAIT_EAP_MSG][RETURN_PAN_PAR_FROM_EAP] = returnPanParFromEap;
    //---------------------------------------------------------------------------------

    table[WAIT_EAP_RESULT][EAP_RESULT] = eapResultStateWaitEapResult;
    //---------------------------------------------------------------------------------

    table[WAIT_EAP_RESULT_CLOSE][EAP_RESULT] = eapResultStateWaitEapResultClose;
    //---------------------------------------------------------------------------------

    table[OPEN][LIVENESS_TEST_INIT_PAC] = livenessTestInitPacStateOpen;
    //---------------------------------------------------------------------------------

    table[OPEN][REAUTH_INIT_PAC] = reauthInitPacStateOpen;
    //---------------------------------------------------------------------------------

    table[OPEN][REAUTH_INIT_PAA] = reauthInitPaaStateOpen;
    //---------------------------------------------------------------------------------

    table[OPEN][SESSION_TERM_INIT_PAA] = sessionTermInitPaaStateOpen;
    //---------------------------------------------------------------------------------

    table[OPEN][SESSION_TERM_INIT_PAC] = sessionTermInitPacStateOpen;
    //---------------------------------------------------------------------------------

    table[WAIT_PNA_REAUTH][REAUTH_INIT_PAC] = reauthInitPacStateWaitPnaReauth;
    //---------------------------------------------------------------------------------

    table[WAIT_PNA_REAUTH][SESSION_TERM_INIT_PAA] = sessionTermInitPaaStateWaitPnaReauth;
    //---------------------------------------------------------------------------------

    table[WAIT_PNA_PING][LIVENESS_TEST_INIT_PAC] = livenessTestInitPacStateWaitPnaPing;
    //---------------------------------------------------------------------------------

    table[WAIT_PNA_PING][REAUTH_INIT_PAA] = reauthInitPaaStateWaitPnaPing;
    //---------------------------------------------------------------------------------

    table[WAIT_PNA_PING][SESSION_TERM_INIT_PAA] = sessionTermInitPaaStateWaitPnaPing;
    //---------------------------------------------------------------------------------

    table[SESS_TERM][SESSION_TERM_INIT_PAC] = sessionTermInitPacStateSessTerm;
    //-----------------------------------------------------------------------//
    //Catch all event on closed state
    table [CLOSED][PAC_INIT_HANDSHAKE] = allEventClosedState;

    table [CLOSED][PAA_INIT_HANDSHAKE] = allEventClosedState;

    table [CLOSED][PAR_PAN_EXCHANGE] = allEventClosedState;

    table [CLOSED][PANA_RESULT] = allEventClosedState;

    table [CLOSED][RETURN_PAN_PAR_FROM_EAP] = allEventClosedState;

    table [CLOSED][EAP_RESULT] = allEventClosedState;

    table [CLOSED][LIVENESS_TEST_INIT_PAC] = allEventClosedState;

    table [CLOSED][REAUTH_INIT_PAC] = allEventClosedState;

    table [CLOSED][REAUTH_INIT_PAA] = allEventClosedState;

    table [CLOSED][SESSION_TERM_INIT_PAA] = allEventClosedState;

    table [CLOSED][SESSION_TERM_INIT_PAC] = allEventClosedState;
}

// Implementation of the functions that check the exit conditions

int pacInitHandshake() {
    if (current_session->client_ctx.AUTH_USER) {
		pana_debug("Sending PCI");
		XFREE(current_session->retr_msg);
		
        current_session->retr_msg = transmissionMessage("PCI", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        
        rtxTimerStart();
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
        return INITIAL;
    } else return ERROR;
}

int paaInitHandshake() {
    // FIXME: A mi me gusta más la sin optimizar
    if (((current_session->PAR.receive = 1) && (current_session->PAR.flags & S_FLAG)) && !(existAvp(current_session->LAST_MESSAGE, "EAP-Payload"))) {
        eapRestart();
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
		XFREE(current_session->retr_msg);
		
        if (generatePanaSa()) { //The initial PAN must be saved
            current_session->retr_msg = transmissionMessage("PAN", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "PRF-Algorithm*Integrity-Algorithm", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        } else {
            current_session->retr_msg = transmissionMessage("PAN", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        }
        
        XFREE(current_session->I_PAN);
		current_session->I_PAN = XMALLOC(char,ntohs(((pana *)current_session->retr_msg)->msg_length));
		memcpy(current_session->I_PAN,current_session->retr_msg,ntohs(((pana *)current_session->retr_msg)->msg_length));
        
        return WAIT_PAA;
    } else return ERROR;
    /* FIXME: Esta es la versión optimizada. Ver si dejamos esta o la otra
     * if (((current_session->PAR.receive) && (current_session->PAR.flags & S_FLAG)) && existAvp(current_session->LAST_MESSAGE,"EAP-Payload" ) && eapPiggyback()) {
        //TODO: El mensaje PAR, será uno de los recibidos por el pac. ¿Pero donde va a estar guardado?
        eapRestart();
        txEAP();
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
        return INITIAL;
    } else if (((current_session->PAR.receive) && (current_session->PAR.flags & S_FLAG)) && existAvp(current_session->LAST_MESSAGE,"EAP-Payload" ) && !eapPiggyback()) {
        eapRestart();
        txEAP();
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
        if (generatePanaSa()) {
            //The S flag is added
            transmissionMessage("PAN", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "PRF-Algorithm*Integrity-Algorithm");
        } else {
            //The S flag is added
            transmissionMessage("PAN", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "");
        }
        return WAIT_EAP_MSG;
    } else if (current_session->client_ctx.EAP_RESPONSE) {
        if (generatePanaSa()) {
            //The S flag is added
            transmissionMessage("PAN", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "EAP-Payload*PRF-Algorithm*Integrity-Algorithm");
        } else {
            //The S flag is added
            transmissionMessage("PAN", S_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "EAP-Payload");
        }
        return WAIT_PAA;
    } else return ERROR;*/
}

int panaResult() {
	int par_result_code=0;
	char * attribute = getAvp(current_session->LAST_MESSAGE, RESULTCODE_AVP);
    if (attribute != NULL) {
		char* value =(((char*)attribute) + sizeof(avp_pana));
		par_result_code = Hex2Dec(value, RESCODE_AVP_VALUE_LENGTH);
    }
    
    if ((current_session->PAR.receive && (current_session->PAR.flags & C_FLAG)) && par_result_code == PANA_SUCCESS) {
        txEAP();
        return WAIT_EAP_RESULT;
    } else if ((current_session->PAR.receive && (current_session->PAR.flags & C_FLAG)) &&  par_result_code != PANA_SUCCESS) {
        if (existAvp(current_session->LAST_MESSAGE, "EAP-Payload")) {
            txEAP();
        } else {
            altReject();
        }
        return WAIT_EAP_RESULT_CLOSE;
    } else return ERROR;
}

int parPanExchange() {
    if (current_session->PAR.receive && (current_session->PAR.flags & R_FLAG) && !eapPiggyback()) {
        rtxTimerStop();
        txEAP();
        eapRespTimerStart();
        XFREE(current_session->retr_msg);
		
        if (current_session->NONCE_SENT == UNSET) {
            current_session->NONCE_SENT = SET;
            XFREE(current_session->PaC_nonce);
			
            //The nonce value must be saved 
            current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "Nonce", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
            int size = ntohs(((pana*)(current_session->retr_msg))->msg_length);
            current_session->PaC_nonce = XMALLOC(char,size);
            memcpy(current_session->PaC_nonce,current_session->retr_msg,size);
        } else {
            current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        }
        return WAIT_EAP_MSG;
    } else if (current_session->PAR.receive && ((current_session->PAR.flags & R_FLAG) == R_FLAG) && eapPiggyback()) {
        rtxTimerStop();
        txEAP();
        eapRespTimerStart();
        return WAIT_EAP_MSG;
    } else if (current_session->PAN.receive) {
        rtxTimerStop();
        return WAIT_PAA;
    } else return ERROR;
}

int returnPanParFromEap() {
    if ((eap_peer_get_eapResp(&(current_session->eap_ctx)) == TRUE) && eapPiggyback()) {
        eapRespTimerStop();
        struct wpabuf * eap_packet = eap_peer_get_eapRespData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = eap_packet;
        
        XFREE(current_session->retr_msg);
        if (current_session->NONCE_SENT == UNSET) {
			XFREE(current_session->PaC_nonce);
            //The nonce value must be saved 
            current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "EAP-Payload*Nonce", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
            int size = ntohs(((pana*)(current_session->retr_msg))->msg_length);
            current_session->PaC_nonce = XMALLOC(char,size);
            memcpy(current_session->PaC_nonce,current_session->retr_msg,size);
            current_session->NONCE_SENT = SET;
        } else {
            current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "EAP-Payload", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        }
        eap_peer_set_eapResp(&(current_session->eap_ctx), FALSE);
        return WAIT_PAA;
    } else if ((eap_peer_get_eapResp(&(current_session->eap_ctx)) == TRUE) && !eapPiggyback()) {
        eapRespTimerStop();
        struct wpabuf * eap_packet = eap_peer_get_eapRespData(&(current_session->eap_ctx));
        current_session->avp_data[EAPPAYLOAD_AVP] = eap_packet;

        if (eap_packet == NULL) {
			pana_debug("ERROR? Strange behaviour, returnPanParFromEap with eap_packet == NULL");
        }

		XFREE(current_session->retr_msg);	
        current_session->retr_msg = transmissionMessage("PAR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "EAP-Payload", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        rtxTimerStart();
        eap_peer_set_eapResp(&(current_session->eap_ctx), FALSE);
        return WAIT_PAA;
    } else if (/*current_session->client_ctx.EAP_RESP_TIMEOUT &&*/ eapPiggyback()) {//Fixme Como se consulta EAP_RESP_TIMEOUT?
		XFREE(current_session->retr_msg);
		current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        return WAIT_PAA;
    } else if (/*current_session->client_ctx.EAP_DISCARD && */eapPiggyback()) {//Fixme Como se consulta?
		XFREE(current_session->retr_msg);
        current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        sessionTimerStop();
        disconnect();
        return CLOSED;
    } else if (eap_peer_get_eapFail(&(current_session->eap_ctx)) == TRUE || (/*current_session->client_ctx.EAP_DISCARD && */!eapPiggyback())) {//Fixme el discard?
        sessionTimerStop();
        disconnect();
        eap_peer_set_eapFail(&(current_session->eap_ctx), FALSE);
        return CLOSED;
    } else return ERROR;
}

int eapResultStateWaitEapResult() {
    if (eap_peer_get_eapSuccess(&(current_session->eap_ctx)) == TRUE) {
		//XFREE(current_session->retr_msg);

        if (existAvp(current_session->LAST_MESSAGE, "Key-Id")/*FIXME: Comprobar que sea PAR*/) {
			
			//The comprobation of C_FLAG may be unnecesary
			XFREE(current_session->retr_msg);
			//Copy key id in current session
			XFREE(current_session->key_id);
			current_session->key_id = XMALLOC(char,current_session->key_id_length);
			avp_pana * kid_avp = (avp_pana*) getAvp(current_session->LAST_MESSAGE, KEYID_AVP);
			memcpy(current_session->key_id,((char *) kid_avp) + sizeof(avp_pana),current_session->key_id_length);
			
            // The C flag is added
            //Key-Id stored in the parameter
            current_session->avp_data[KEYID_AVP] = current_session->key_id;
            current_session->retr_msg =  transmissionMessage("PAN", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "Key-Id", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        } else {
            // The C flag is added
            current_session->retr_msg =  transmissionMessage("PAN", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        }
        
        authorize();
        sessionTimerReStart(current_session->LIFETIME_SESS_TIMEOUT);
        eap_peer_set_eapSuccess(&(current_session->eap_ctx), FALSE);
        return OPEN;
    } else if (eap_peer_get_eapFail(&(current_session->eap_ctx)) == TRUE) {
		XFREE(current_session->retr_msg);
        // The C flag is added
        current_session->retr_msg = transmissionMessage("PAN", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        sessionTimerStop();
        disconnect();
        eap_peer_set_eapFail(&(current_session->eap_ctx), FALSE);
        return CLOSED;
    } else{
		 return ERROR;
	 }
}

int eapResultStateWaitEapResultClose() {
    if (eap_peer_get_eapSuccess(&(current_session->eap_ctx)) == TRUE || eap_peer_get_eapFail(&(current_session->eap_ctx)) == TRUE) {
		XFREE(current_session->retr_msg);
        if (eap_peer_get_eapSuccess(&(current_session->eap_ctx)) == TRUE && existAvp(current_session->LAST_MESSAGE, "Key-Id")) {
            // The C flag is added
            //Key-Id stored in the parameter
            current_session->avp_data[KEYID_AVP] = current_session->key_id;
            current_session->retr_msg = transmissionMessage("PAN", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "Key-Id", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        } else {
            // The C flag is added
            current_session->retr_msg = transmissionMessage("PAN", C_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        }
        sessionTimerStop();
        disconnect();

        if (eap_peer_get_eapSuccess(&(current_session->eap_ctx)) == TRUE) {
            eap_peer_set_eapSuccess(&(current_session->eap_ctx), FALSE);
        }
        if (eap_peer_get_eapFail(&(current_session->eap_ctx)) == TRUE) {
            eap_peer_set_eapFail(&(current_session->eap_ctx), FALSE);
        }

        return CLOSED;
    } else return ERROR;
}

int livenessTestInitPacStateOpen() {
    if (current_session->PANA_PING) {
		XFREE(current_session->retr_msg);
        //P_FLAG is added.
        current_session->retr_msg = transmissionMessage("PNR", P_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        rtxTimerStart();
        return WAIT_PNA_PING;
    } else return ERROR;
}

int reauthInitPacStateOpen() {
    if (current_session->REAUTH) {
        current_session->NONCE_SENT = UNSET;
		XFREE(current_session->retr_msg);
        //A_FLAG is added
        current_session->retr_msg = transmissionMessage("PNR", A_FLAG, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        rtxTimerStart();
        return WAIT_PNA_REAUTH;
    } else return ERROR;
}

int reauthInitPaaStateOpen() {
    if (current_session->PAR.receive) {
        eapRespTimerStart();
        txEAP();
        if (!eapPiggyback()) {
			XFREE(current_session->retr_msg);
            current_session->retr_msg = transmissionMessage("PNR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "Nonce", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        } else {
            current_session->NONCE_SENT = UNSET;
        }
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int sessionTermInitPaaStateOpen() {
    if (current_session->PTR.receive) {
		XFREE(current_session->retr_msg);
        current_session->retr_msg = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);

        sessionTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

int sessionTermInitPacStateOpen() {
    if (current_session->TERMINATE) {
        current_session->avp_data[TERMINATIONCAUSE_AVP] =(void*) LOGOUT;
        XFREE(current_session->retr_msg);
        current_session->retr_msg = transmissionMessage("PTR", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        rtxTimerStart();
        sessionTimerStop();
        return SESS_TERM;
    } else return ERROR;
}

int reauthInitPacStateWaitPnaReauth() {
    if ((current_session->PNA.receive) && (current_session->PNA.flags && A_FLAG)) {
        rtxTimerStop();
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
        return WAIT_PAA;
    } else return ERROR;
}

int sessionTermInitPaaStateWaitPnaReauth() {
    if (current_session->PTR.receive) {
        rtxTimerStop();
        XFREE(current_session->retr_msg);
		
		current_session->retr_msg = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        sessionTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

int livenessTestInitPacStateWaitPnaPing() {
    if ((current_session->PNA.receive) && (current_session->PNA.flags && P_FLAG)) {
        rtxTimerStop();
        return OPEN;
    } else return ERROR;
}

int reauthInitPaaStateWaitPnaPing() {
    if (current_session->PAR.receive) {
        rtxTimerStop();
        eapRespTimerStart();
        txEAP();
        if (!eapPiggyback()) {
			
			XFREE(current_session->retr_msg);
			
            current_session->retr_msg = transmissionMessage("PAN", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "Nonce", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        } else {
            current_session->NONCE_SENT = UNSET;
        }
        sessionTimerReStart(current_session->client_ctx.FAILED_SESS_TIMEOUT);
        return WAIT_EAP_MSG;
    } else return ERROR;
}

int sessionTermInitPaaStateWaitPnaPing() {
    if (current_session->PTR.receive) {
        rtxTimerStop();
        XFREE(current_session->retr_msg);
		
		current_session->retr_msg  = transmissionMessage("PTA", 0, &(current_session->SEQ_NUMBER), current_session->session_id, "", current_session->eap_ll_dst_addr, current_session->avp_data, current_session->socket);
        sessionTimerStop();
        disconnect();
        return CLOSED;
    } else return ERROR;
}

int sessionTermInitPacStateSessTerm() {
    if (current_session->PTA.receive) {
        disconnect();
        return CLOSED;
    } else return ERROR;
}


//*******************************************************//
// Procedures' implementation

int eapPiggyback() {
	pana_debug("eapPiggyback function"); //TODO: Falta la implementación
    return 0;
}

void altReject() {
	pana_debug("altReject function"); //TODO: Falta la implementación
}

void eapRespTimerStart() {
	pana_debug("eapRespTimerStart function"); //TODO: Falta la implementación
}

void eapRespTimerStop() {
	pana_debug("eapRespTimerStop function"); //TODO: Falta la implementación
}
