/**
 * @file pacmachine.h
 * @brief  Headers of PaC's state machine specific functions.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 18/03/10.
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
#ifndef PACMACHINE_H
#define PACMACHINE_H

#include "../include.h"

// Events
/** PaC-initiated Handshake event. */
#define PAC_INIT_HANDSHAKE      0
/** PAA-initiated Handshake event. */
#define PAA_INIT_HANDSHAKE 		1
/** PANA result event. */
#define PANA_RESULT				2
/** PAR-PAN exchange event. */
#define PAR_PAN_EXCHANGE   		3
/** Return PAN/PAR from EAP event. */
#define RETURN_PAN_PAR_FROM_EAP	4
/** EAP result event.*/
#define EAP_RESULT				5
/** Liveness test initiated by PaC event. */
#define LIVENESS_TEST_INIT_PAC	6
/** Session termination initiated by PAA event. */
#define SESSION_TERM_INIT_PAA	7
/** Session termination initiated by PaC event. */
#define SESSION_TERM_INIT_PAC	8
/** Re-authentication initiated by PaC event. */
#define REAUTH_INIT_PAC			9
/** Re-authentication initiated by PAA event. */
#define REAUTH_INIT_PAA			10

// Procedures
/**
 * This procedure returns TRUE to indicate whether the next EAP
 * response will be carried in the pending PAN message for
 * optimization.
 */
int eapPiggyback();
/**
 * This procedure informs the EAP peer of an authentication failure
 * event without accompanying an EAP message.
 */
void altReject();
/**
 * This is a procedure to start a timer to receive an EAP-Response
 * from the EAP peer.
 */
void eapRespTimerStart();
/**
 * This is a procedure to stop a timer to receive an EAP-Response
 * from the EAP peer.
 */
void eapRespTimerStop();

// Functions that check the exit condition and do the exit action
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int pacInitHandshake();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int paaInitHandshake();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int parPanExchange();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int panaResult();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int returnPanParFromEap();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int eapResultStateWaitEapResult();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int eapResultStateWaitEapResultClose();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int livenessTestInitPacStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int livenessTestInitPacStateWaitPnaPing();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPacStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPacStateWaitPnaReauth();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPaaStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int reauthInitPaaStateWaitPnaPing();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPacStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPacStateSessTerm();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPaaStateOpen();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPaaStateWaitPnaReauth();
/** Checks the exit condition of the event of equal name, doing meanwhile
 * the operations needed. 
 * See RFC 5609 Section 7.5 for further detail.
 * 
 * @return Next state to make the transition to.
 * @return ERROR if an error ocurred.
 * */
int sessionTermInitPaaStateWaitPnaPing();

/**
 * Initializes the PaC transition table.
 * */
 void initPacTable();

#endif
