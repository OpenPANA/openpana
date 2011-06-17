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
#ifndef PAAMACHINE
#define PAAMACHINE

// Events
#define PCI_PAA_INIT_PANA		4
#define PAN_HANDLING			5
#define RECEIVING_EAP_REQUEST		6
#define RX_EAP_SUCCESS_FAILURE		7
#define RX_EAP_TIMEOUT_INVALID_MSG 	8
#define PAN_PROCESSING			9
#define REAUTH_INIT_PAC			10
#define REAUTH_INIT_PAA			11
#define LIVENESS_TEST_EX_INIT_PAA	12
#define SESSION_TERM_INIT_PAA		13
#define SESSION_TERM_INIT_PAC		14
#define PNA_PROCESSING			15
#define PAR_PROCESSING			16
#define PASS_EAP_RESP_TO_EAP_AUTH	17
#define PAN_WITHOUT_EAP_RESPONSE	18
#define EAP_RETRANSMISSION		19
#define EAP_AUTH_TIMEOUT_FAILURE	20
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
int pciPaaInitPana();
int panHandling();
int receivingEapRequest();
int rxEapSuccessFailure();
int rxEapTimeoutInvalidMsg();
int panProcessingStateWaitSuccPan();
int panProcessingStateWaitFailPan();
int reauthInitPacStateOpen();
int reauthInitPacStateWaitPnaPing();
int reauthInitPaa();
int livenessTestExInitPaa();
int sessionTermInitPaa();
int sessionTermInitPacStateOpen();
int sessionTermInitPacStateWaitPnaPing();
int pnaProcessing();
int parProcessing();
int passEapRespToEapAuth();
int panWithoutEapResponse();
int eapRetransmission();
int eapAuthTimeoutFailure();
int ptaProcessing();

/**
 * Initializes the PAA transition table.
 * */
void initPaaTable();
#endif
