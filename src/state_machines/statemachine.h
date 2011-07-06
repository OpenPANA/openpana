/*
 *  statemachine.h
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
#ifndef STATEMACHINE
#define STATEMACHINE
#include "session.h"

//FIXME: Esto debería ir en un include.h???
#define SET		1
#define UNSET 	0
#define ERROR	-666

// Values of a result code avp
/**
 * Both authentication and authorization processes are successful.
 */
#define PANA_SUCCESS					0
/**
 * Authentication has failed. When authentication fails,
 * authorization is also considered to have failed.
 */
#define PANA_AUTHENTICATION_REJECTED	1
/**
 * The authorization process has failed. This error could occur when
 * authorization is rejected by a AAA server or rejected locally by a
 * PAA, even if the authentication procedure has succeeded.
 */
#define PANA_AUTHORIZATION_REJECTED		2

// Values of a termination cause avp
/**
 * The client initiated a disconnect.
 */
#define LOGOUT	1
/**
 * The client was not granted access or was disconnected due to
 * administrative reasons.
 */
#define ADMINISTRATIVE	4
/**
 * The session has timed out, and service has been terminated.
 */
#define SESSION_TIMEOUT	 8

/** Number of events available for both of paa and pac state machines */
#define NUM_STATES	13
/** Number of differents Events in Paa statemachine because its greater
 *  than the 15 Events needed in Pac statemachine, so the transition
 *  table must be at least this big. */
#define NUM_EVENTS	22

// States
/** The state doesn't change. */
#define NO_CHANGE 				-1
/** Initial state.*/
#define INITIAL 				0
#define WAIT_PNA_PING 			1
/**Closed state.*/
#define CLOSED					2
#define WAIT_PAA 				3
#define WAIT_EAP_MSG			4
#define WAIT_EAP_RESULT 		5
#define WAIT_EAP_RESULT_CLOSE	6
#define OPEN					7
#define WAIT_PNA_REAUTH			8
#define SESS_TERM				9
#define WAIT_PAN_OR_PAR			10
#define WAIT_FAIL_PAN			11
#define WAIT_SUCC_PAN			12

// Events
#define RETRANSMISSION			0
#define REACH_MAX_NUM_RT		1
#define LIVENESS_TEST_PEER		2
#define LIVENESS_TEST_RESPONSE  3


/** General callback function definition, it corresponds to a function
 * to be called in a position of the state machine table */
typedef int (*function)();

/** State transition table is used to represent the operation of the 
 * protocol by a number of cooperating state machines each comprising a 
 * group of connected, mutually exclusive states. Only one state of each
 * machine can be active at any given time. Rows are the states and
 * columns are the events. By invoking the table with a state and
 * associated event, the corresponding callback function is called. */
function table [NUM_STATES][NUM_EVENTS];

/** Pointer to the current PANA session.*/
pana_ctx * current_session;

// Functions' headers
/**
 * Initializes the common transition table between PaC and PAA.
 * */
void initTable();

/**
 * Change the state of the state machine if a transition has to be made.
 * @return ERROR If an error ocurred during transition.
 * @return 0 If the function worked properly.
 * */
int transition(pana_ctx *pana_session);

// Functions that do the exit action
/**
 *  A null procedure, where nothing is done.
 */
void none();
/**
 * A procedure to delete the PANA session as well as the
 * corresponding EAP session and authorization state.
 */
void disconnect();
/**
 * A procedure to create or modify authorization state.
 * 
 * It is assumed that authorize() procedure of PaC state machine
 * always returns TRUE. In the case that a non-key-generating EAP
 * method is used but a PANA SA is required after successful
 * authentication (generate_pana_sa() returns TRUE), authorize()
 * procedure must return FALSE.
 *  
 * @return 1 If authorization is successful. 
 * @return 0 If authorization is unsuccessful.
 */
int authorize();
/**
 * A procedure to send an EAP message to the EAP state machine to
 * which it interfaces.
 */
void txEAP();
/**
 * A procedure to start the retransmission timer, reset RTX_COUNTER
 * variable to zero, and set an appropriate value to RTX_MAX_NUM
 * variable. Note that RTX_MAX_NUM is assumed to be set to the same
 * default value for all messages. However, implementations may also
 * reset RTX_MAX_NUM in this procedure and its value may vary
 * depending on the message that was sent.
 */
void rtxTimerStart();
/**
 * A procedure to stop the retransmission timer.
 */
void rtxTimerStop();
/**
 * A procedure to (re)start the PANA session timer. It'll be restarted 
 * with the specified expiration time associated with the session timer.
 * Expiration of TIMEOUT will trigger a SESS_TIMEOUT event.
 * 
 * @param timeout Time to be set as session timer.
 */
void sessionTimerReStart(int timeout);
/**
 * A procedure to stop the current PANA session timer.
 */
void sessionTimerStop();
/**
 *A procedure to retransmit a PANA message and increment RTX_COUNTER
 * by one(1).
 */
void retransmit();
/**
 * A procedure to (re)start an EAP conversation resulting in the re-
 * initialization of an existing EAP session.
 */
void eapRestart();
/**
 * A procedure to check whether the EAP method being used generates
 * keys and that a PANA SA will be established on successful
 * authentication. For the PaC, the procedure is also used to check
 * and match the PRF and Integrity algorithm AVPs advertised by the
 * PAA in PAR[S] message. For the PAA, it is used to indicate
 * whether a PRF and Integrity algorithm AVPs will be sent in the
 * PAR[S].
 * 
 * @return 1 If a PANA SA will be generated.
 * @return 0 Otherwise.
 */
int generatePanaSa();
/**
 * A procedure to check whether the PANA session has a PANA_AUTH_KEY.
 * If the state machine does not have a PANA_AUTH_KEY, it tries to
 * retrieve a Master Session Key (MSK) from the EAP entity. If an
 * MSK is retrieved, it computes a PANA_AUTH_KEY from the MSK and
 * returns TRUE.
 * 
 * @return 1 If the state machine already has a PANA_AUTH_KEY or it can
 *  be correctly generated.
 * @return 0 Otherwise.
 */
int keyAvailable();

// Functions that check the condition, do the action and return 
/**
 * A procedure to check the retransmission condition in the state 
 * machine and retransmit if needed.
 * 
 * @return NO_CHANGE If a retrasmission has been made.
 * @return ERROR If no retransmission needed.
 * */
int retransmission();
/**
 * A procedure to check the maximum number of retransmission has been 
 * reached in the state machine and disconnects if needed.
 * 
 * @return CLOSED If the state machine has disconnected.
 * @return ERROR If no disconnection needed.
 * */
int reachMaxNumRt();
int livenessTestPeer();
int livenessTestResponse();
/**
 * A procedure to use during the CLOSE state with any event, it does nothing.
 * @return CLOSED Always.
 * */
int allEventClosedState();
#endif
