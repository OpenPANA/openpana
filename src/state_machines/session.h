/*
 *  session.h
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
#ifndef SESSION
#define SESSION

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef ISCLIENT //Include session variables only for PANA clients
#include "sessionclient.h"
#include "../libeapstack/eap_peer_interface.h"
/**
 * Declaration of client configurable variables
 * */
int PRF_HMAC_SHA1;
int AUTH_HMAC_SHA1_160;
int FAILED_SESS_TIMEOUT_CONFIG;
short SRCPORT;
short DSTPORT;
char* DESTIP;
char* LOCALIP;
#endif

#ifdef ISSERVER //Include session variables only for PANA servers
#include "sessionserver.h"
#include "../libeapstack/eap_auth_interface.h"
/**
 * Declaration of client configurable variables
 * */
int PRF_HMAC_SHA1;
int AUTH_HMAC_SHA1_160;
int SRCPORT;
int LIFETIME_SESSION_TIMEOUT_CONFIG;
int LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG;
int TIME_PCI;
int NUM_WORKERS;
#endif

#include "../panamessages.h"
#include "../loadconfig.h"

/** Max Request retry attempts. See rfc 3315*/
#define REQ_MAX_RC	10 

/** Max Request timeout value. See rfc 3315*/
#define REQ_MAX_RT	30 
/// Struct of a pana message flags

typedef struct {
    int result_code;
    int receive;
    short flags;
} pana_msg_flags;
/**
 * Struct containing all variables needed to define a PANA session.
 * */
typedef struct {
    unsigned short src_port;
    unsigned short dst_port;
    
    // Common Variables
    /**
     * This event variable is set to TRUE when the retransmission timer
     * is expired.
     */
    int RTX_TIMEOUT;
    /**
     * This variable contains the current number of retransmissions of
     * the outstanding PANA message.
     */
    int RTX_COUNTER;
    /**
     *  This variable is set to TRUE to indicate that a Nonce-AVP has
     *  already been sent.  Otherwise, it is set to FALSE.
     */
    int NONCE_SENT;
    /**
     * This event variable is set to TRUE when an initiation of re-
     * authentication phase is triggered.  This event variable can only
     * be set while in the OPEN state.
     */
    int REAUTH;
    /**
     * This event variable is set to TRUE when initiation of PANA session
     * termination is triggered.  This event variable can only be set
     * while in the OPEN state.
     */
    int TERMINATE;
    /**
     * This event variable is set to TRUE when initiation of liveness
     * test based on PANA-Notification exchange is triggered.  This event
     * variable can only be set while in the OPEN state.
     */
    int PANA_PING;
    /**
     *  This event is variable is set to TRUE when the session timer has
     *  expired.
     */
    int SESS_TIMEOUT;
    /**
     * Configurable value used by the PaC and PAA to close or disconnect
     * an established session in the access phase.  This variable
     * indicates the expiration of the session and is set to the value of
     * Session-Lifetime AVP if present in the last PANA-Auth-Request
     * message in the case of the PaC.  Otherwise, it is assumed that the
     * value is infinite and therefore has no expiration.  Expiration of
     * LIFETIME_SESS_TIMEOUT will cause the event variable SESS_TIMEOUT
     * to be set.
     */
    int LIFETIME_SESS_TIMEOUT;
    /**
     * This event variable is set to TRUE when any event occurs.
     */
    int ANY;
    /**
     * This event variable is set with the current state of the client/server
     */
    int CURRENT_STATE;
    /**
     * This event variable is set with the number of the package number in the sequence
     */
    int SEQ_NUMBER;
    /**
     * This event variable is set with the last Pana Message received
     */
    char *LAST_MESSAGE;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PNR;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PNA;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PAR;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PTR;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PTA;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PAN;
    /**
     * This event variable is set to TRUE when the specified PANA message
     * is received from its peering PANA entity. The "flag" contains a
     * flag (e.g., Rx:PAR[C]), except for ’R’ (Request) flag.
     */
    pana_msg_flags PCI;


    //PanaMessages needed to generate the pana AUTH key
    char * I_PAR; //They are stored in the serialized way
    char * I_PAN;
    
    //PANA SA Attributes
    char * PaC_nonce;
    char * PAA_nonce;

	/**Contains MSK key value when generated.*/
    u8 * msk_key;
    /**MSK key length.*/
    unsigned int key_len;
    
    /** Stores the actual MSK Identifier (Key_id) */
    char * key_id; //MSK Identifier = Key_id
    /** Key_id's variable length*/
    int key_id_length;
    
    //Data ptrs to fill with AVPs information,
    //its size is from the last avp defined
    /** AVP data to fill with information that will be used by AVPs when
     * needed.*/
    void *avp_data[TERMINATIONCAUSE_AVP + 1];
    /**Alarm list.*/
    struct lalarm** list_of_alarms;
    /** Last message sended, to use during retransmissions.*/
    char * retr_msg;
#ifdef ISCLIENT //Include session variables only for PANA clients
	/** PANA variables only for PANA Clients. */
    pana_client_ctx client_ctx;
	/** EAP variables only for PANA Clients. */
    struct eap_peer_ctx eap_ctx;
#endif

#ifdef ISSERVER //Include session variables only for PANA servers
	/** PANA variables only for PANA Servers. */
    pana_server_ctx server_ctx;
	/** EAP variables only for PANA Servers. */
    struct eap_auth_ctx eap_ctx;

    /** Number of retransmission to AAA*/
    int RTX_COUNTER_AAA;
#endif

	struct sockaddr_in eap_ll_dst_addr;
    int addr_size;
    int eap_ll_sock;
    int session_id;
    int prf_alg;
    int integ_alg;
    int socket;
    pthread_mutex_t mutex;
    
    // Configurable values
    /**
     * Configurable maximum for how many retransmissions should be
     * attempted before aborting.
     */
    int RTX_MAX_NUM;

   
    // Retransmissions variables
    /** Retransmission timeout from the previous (re)transmission*/
    float RT;
    /** Base value for RT for the initial retransmission*/
    float IRT;
    /** Maximum retransmission count*/
    float MRC;
    /**Maximum retransmission time*/
    float MRT;
    /**Maximum retransmission duration*/
    float MRD;
    /**Randomization factor*/
    float RAND;

} pana_ctx;

// Procedures
/** Initializes the pana_ctx structure refered to a new PANA session. */
void initSession(pana_ctx * pana_session);
/** Updates the session given a PANA message.*/
void updateSession(char *message, pana_ctx *pana_session);
/** Resets the PANA session. */ 
void resetSession();
#endif
