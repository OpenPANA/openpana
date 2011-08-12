/*
 *  paamachine.h
 *
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
#ifndef PAAMACHINE_H
#define PAAMACHINE_H

#include "session.h"

// Events
/** PCI and PAA initiated PANA event.*/
#define PCI_PAA_INIT_PANA		4
/** PAN handling event. */
#define PAN_HANDLING			5
/** Receiving EAP request event. */
#define RECEIVING_EAP_REQUEST		6
/** Receiving EAP request/failure event. */
#define RX_EAP_SUCCESS_FAILURE		7
/** Receiving EAP-Timeout or invalid message event. */
#define RX_EAP_TIMEOUT_INVALID_MSG 	8
/** PAN processing event. */
#define PAN_PROCESSING			9
/** Re-authentication initiated by PAC event. */
#define REAUTH_INIT_PAC			10
/** Re-authentication initiated by PAA event. */
#define REAUTH_INIT_PAA			11
/** Liveness test based on PNR-PNA exchange initiated by PAA event. */
#define LIVENESS_TEST_EX_INIT_PAA	12
/** Session termination initiated from PAA event.*/
#define SESSION_TERM_INIT_PAA		13
/** Session termination initiated from PaC event. */
#define SESSION_TERM_INIT_PAC		14
/** PNA processing event. */
#define PNA_PROCESSING			15
/** PAR processing event. */
#define PAR_PROCESSING			16
/** Pass EAP Response to the EAP authenticator event. */
#define PASS_EAP_RESP_TO_EAP_AUTH	17
/** PAN without an EAP response event. */
#define PAN_WITHOUT_EAP_RESPONSE	18
/** EAP retransmission event. */
#define EAP_RETRANSMISSION		19
/** EAP authentication timeout or failure event. */
#define EAP_AUTH_TIMEOUT_FAILURE	20
/** PTA processing event. */
#define PTA_PROCESSING			21

// Procedures
/**
 * Procedure to check whether the PANA session has a new
 * PANA_AUTH_KEY. If the state machine already has a PANA_AUTH_KEY,
 * it returns FALSE. If the state machine does not have a
 * PANA_AUTH_KEY, it tries to retrieve an MSK from the EAP entity.
 * If an MSK has been retrieved, it computes a PANA_AUTH_KEY from the
 * MSK and returns TRUE. Otherwise, it returns FALSE.
 */
int newKeyAvailable();

// Functions that check the exit condition
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int pciPaaInitPana();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int panHandling();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int receivingEapRequest();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int rxEapSuccessFailure();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int rxEapTimeoutInvalidMsg();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int panProcessingStateWaitSuccPan();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int panProcessingStateWaitFailPan();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPacStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPacStateWaitPnaPing();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPaa();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int livenessTestExInitPaa();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPaa();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPacStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPacStateWaitPnaPing();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int pnaProcessing();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int parProcessing();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int passEapRespToEapAuth();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int panWithoutEapResponse();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int eapRetransmission();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int eapAuthTimeoutFailure();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 8.4 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int ptaProcessing();

/**
 * Initializes the PAA transition table.
 * */
void initPaaTable(pana_ctx *pana_session );

#endif
