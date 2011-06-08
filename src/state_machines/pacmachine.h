/*
 *  pacmachine.h
 *
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
#ifndef PACMACHINE
#define PACMACHINE

// Events
#define PAC_INIT_HANDSHAKE      4
#define PAA_INIT_HANDSHAKE 	5
#define PANA_RESULT		6
#define PAR_PAN_EXCHANGE   	7
#define RETURN_PAN_PAR_FROM_EAP	8
#define EAP_RESULT		9
#define LIVENESS_TEST_INIT_PAC	10
#define SESSION_TERM_INIT_PAA	11
#define SESSION_TERM_INIT_PAC	12
#define REAUTH_INIT_PAC		13
#define REAUTH_INIT_PAA		14

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
int pacInitHandshake();
int paaInitHandshake();
int parPanExchange();
int panaResult();
int returnPanParFromEap();
int eapResultStateWaitEapResult();
int eapResultStateWaitEapResultClose();
int livenessTestInitPacStateOpen();
int livenessTestInitPacStateWaitPnaPing();
int reauthInitPacStateOpen();
int reauthInitPacStateWaitPnaReauth();
int reauthInitPaaStateOpen();
int reauthInitPaaStateWaitPnaPing();
int sessionTermInitPacStateOpen();
int sessionTermInitPacStateSessTerm();
int sessionTermInitPaaStateOpen();
int sessionTermInitPaaStateWaitPnaReauth();
int sessionTermInitPaaStateWaitPnaPing();


//Init functions
void initPacTable();

#endif
