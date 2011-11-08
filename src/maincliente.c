/**
 * @file maincliente.c
 * @brief  PaC's main program.
 **/
/*
 *  Created by Rafa Marin Lopez on 27/10/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 * 	Modified by Pedro Moreno Sánchez and Francisco Vidal Meca on 15/11/10
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
 
#include "maincliente.h"

#include "state_machines/statemachine.h"
#include "panamessages.h"
#include "state_machines/pacmachine.h"
#include "panautils.h"
#include "state_machines/session.h"
#include "./libeapstack/eap_peer_interface.h"
#include "lalarm.h"


static int signal_received = FALSE;
/** Alarm's list, cointains all the alarms setted by the PaC to perform 
 * future actions.*/
struct lalarm* list_alarms = NULL; // alarms' list
/** Mutex to access alarm's list list_alarms.*/
pthread_mutex_t alarm_list_mutex;
/** PANA data of the client's session. */
pana_ctx pana_session;
/** Mutex to access to PANA session pana_session. */
pthread_mutex_t session_mutex;

void signal_handler(int sig) {
	pana_debug("Client's exit petition, signal: %d", sig);
    signal_received = TRUE;
}

void* handle_alarm_management(void* none) {

    while (TRUE){
		
		double time = getTime();

		struct lalarm* alarm = NULL;
		while ((alarm=get_next_alarm(&list_alarms, time)) != NULL){
			 if (alarm->id == RETR_ALARM) {
				pana_debug("A PANA_RETRANSMISSION alarm ocurred");
				pthread_mutex_lock(&session_mutex);
				alarm->pana_session->RTX_TIMEOUT = 1;
				transition(alarm->pana_session);
				pthread_mutex_unlock(&session_mutex);
			} else if (alarm->id == SESS_ALARM) {
				pana_debug("A SESSION alarm ocurred");
				pthread_mutex_lock(&session_mutex);
				alarm->pana_session->REAUTH = 1;
				eapRestart();
				transition(alarm->pana_session);
				pthread_mutex_unlock(&session_mutex);
			} else if (alarm->id == PING_ALARM) {
				pana_debug("A PING alarm ocurred");
				pthread_mutex_lock(&session_mutex);
				alarm->pana_session->PANA_PING = 1;
				eapRestart();
				transition(alarm->pana_session);
				pthread_mutex_unlock(&session_mutex);
			}
			else {
				pana_debug("An UNKNOWN alarm ocurred");
			}
		}
		waitusec(TIME_WAKE_UP);
	}
}

int main(int argc, char *argv[]) {

    struct sockaddr_in eap_auth_ll_sockaddr; //For IPv4 support
    struct sockaddr_in6 eap_auth_ll_sockaddr6; //For IPv6 support
    fd_set readfds, exceptfds; //FD sets to use with select
    int pana_sock;//PANA's socket

	printf("\n%s Client - %s",PACKAGE_NAME,PACKAGE_VERSION);
	printf("\n%s\n\n",PACKAGE_URL);
    printf("Copyright (C) 2011  Pedro Moreno Sánchez and Francisco Vidal Meca\n");
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions, see COPYING for details.\n\n");
	
	pthread_t alarm_thread;

	//Init the session mutex
	pthread_mutex_init(&session_mutex, NULL);
	
    //PANA session is initialized
    initSession(&pana_session); 
    initPacTable();
    
    
    //The client is the autentication's initiator
    pana_session.client_ctx.AUTH_USER = 1;
    
    list_alarms = init_alarms(&alarm_list_mutex);
	pana_session.list_of_alarms = &(list_alarms);
	pthread_create(&alarm_thread, NULL, handle_alarm_management, NULL);

	//To handle exit signals
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

	if (IP_VERSION==4){
		if ((pana_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			perror("PANA: socket");
			return -1;
		}
	}
	else if (IP_VERSION==6){
		if ((pana_sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
			perror("PANA: socket");
			return -1;
		}
	}

    int b = 1;
    // SO_REUSEADDR option is used in case of an unexpected exit, the
    // client will be able to reuse the socket
    if (setsockopt(pana_sock, SOL_SOCKET, SO_REUSEADDR, &b, 4)) {
        perror("PANA: setsockopt");
        return 0;
    }

	if (IP_VERSION==4){
		struct sockaddr_in ipbind;
		ipbind.sin_family = AF_INET;
		ipbind.sin_port = SRCPORT;
		inet_pton(AF_INET, LOCALIP, &ipbind.sin_addr);
		const struct sockaddr * sockaddr = (struct sockaddr *) & ipbind;
		if (bind(pana_sock, sockaddr, sizeof(ipbind))){
			perror("bind");
			pana_error("bind in mainCliente");
		}
	}
	else if (IP_VERSION==6){
		struct sockaddr_in6 ipbind6;
		ipbind6.sin6_family = AF_INET6;
		ipbind6.sin6_port = SRCPORT;
		inet_pton(AF_INET6, LOCALIP, &ipbind6.sin6_addr);
		const struct sockaddr * sockaddr = (struct sockaddr *) & ipbind6;
		if (bind(pana_sock, sockaddr, sizeof(ipbind6))){
			perror("bind");
			pana_error("bind in mainCliente");
		}
	}
	//Update the socket number in the session.
	pana_session.socket = pana_sock;

	if (IP_VERSION==4){
		eap_auth_ll_sockaddr.sin_family = AF_INET;
		eap_auth_ll_sockaddr.sin_port = pana_session.eap_ll_dst_addr.sin_port;
		inet_pton(AF_INET, LOCALIP, &eap_auth_ll_sockaddr.sin_addr);
	}
	else if (IP_VERSION==6){
		eap_auth_ll_sockaddr6.sin6_family = AF_INET6;
		eap_auth_ll_sockaddr6.sin6_port = pana_session.eap_ll_dst_addr6.sin6_port;
		inet_pton(AF_INET6, LOCALIP, &eap_auth_ll_sockaddr6.sin6_addr);
	}

    //Step pana state machine
    pthread_mutex_lock(&session_mutex);
    transition(&pana_session);
    pthread_mutex_unlock(&session_mutex);

	struct sockaddr_in eap_auth_ll_addr;
	struct sockaddr_in6 eap_auth_ll_addr6;
	int addr_size=0;
	char pana_packet[MAX_DATA_LEN];
	
	//Until a termination signal is received, the client must be working
    while (!signal_received) { 
		addr_size=0;
        
        FD_ZERO(&readfds); //Setting to 0 FDsets
        FD_ZERO(&exceptfds);
        FD_SET(pana_sock, &readfds); //Assigning the FDs to pana socket
        FD_SET(pana_sock, &exceptfds);

        if (IP_VERSION==4)
			addr_size = sizeof (eap_auth_ll_addr);
		else if (IP_VERSION==6)
			addr_size = sizeof (eap_auth_ll_addr6);
        
        pana_debug("I'm gonna start listening!");
        pana_debug("My state is: %s", state_name[pana_session.CURRENT_STATE + 1]);

		//Wait for net events
        if (select(FD_SETSIZE, &readfds, NULL, &exceptfds, NULL) < 0) {
            perror("select");
            break;
        }

		//If a PANA packet is received
        if (FD_ISSET(pana_sock, &readfds)) {
            uint16_t length =0;
            if (IP_VERSION==4)
				length = recvfrom(pana_sock, pana_packet, sizeof (pana_packet), 0, (struct sockaddr *) &eap_auth_ll_addr, (socklen_t *) & addr_size);
			else if (IP_VERSION==6)
				length = recvfrom(pana_sock, pana_packet, sizeof (pana_packet), 0, (struct sockaddr *) &eap_auth_ll_addr6, (socklen_t *) & addr_size);
			//length is >0 when it's correctly received only
            if (length > 0) {

                pthread_mutex_lock(&session_mutex);
                updateSession(pana_packet, &pana_session);
                pthread_mutex_unlock(&session_mutex);
                
                pana_debug("My state to begin a transition is: %s", state_name[pana_session.CURRENT_STATE + 1]);
                
				pthread_mutex_lock(&session_mutex);
                transition(&pana_session);
                pthread_mutex_unlock(&session_mutex);
            }

            //Check if eap authentication has finished with a fail
                if (eap_peer_get_eapFail(&(current_session->eap_ctx)) == TRUE) {
					pana_debug("There's an eapFail");
					pthread_mutex_lock(&session_mutex);
                    transition(&pana_session);
                    pthread_mutex_unlock(&session_mutex);
                }
            
                //Check if exist a Response for eap server
                if (eap_peer_get_eapResp(&(pana_session.eap_ctx)) == TRUE) {
					pana_debug("There's an EAPResponse");
                    pthread_mutex_lock(&session_mutex);
                    transition(&pana_session);
                    pthread_mutex_unlock(&session_mutex);

                }

                //Check if eap authentication has finished with success
                if (eap_peer_get_eapSuccess(&(current_session->eap_ctx)) == TRUE) {
					pana_debug("There's an eapSuccess");
                    pthread_mutex_lock(&session_mutex);
                    transition(&pana_session);
                    pthread_mutex_unlock(&session_mutex);
                }

				
				//FIXME: Este if no debería ser necesario siguiendo el rfc.
                if (current_session->CURRENT_STATE == WAIT_EAP_RESULT_CLOSE){
					if (eap_peer_get_eapResp(&(pana_session.eap_ctx)) == TRUE) {
						eap_peer_set_eapFail(&(current_session->eap_ctx), TRUE);
						pthread_mutex_lock(&session_mutex);
						transition(&pana_session);
						pthread_mutex_unlock(&session_mutex);
					}
				}

				if (current_session->CURRENT_STATE == OPEN){
					//////////// ACCESS PHASE ////////////

					if (NUMBER_PING_AUX){
						NUMBER_PING_AUX = NUMBER_PING_AUX-1;
						add_alarma(&list_alarms, &pana_session, PING_TIME, PING_ALARM);
					}else{ // Reset the number of ping messages to be exchanged when the
						   // next access phase is reached.
						NUMBER_PING_AUX = NUMBER_PING;
					}
					
				}

				
            }//length >0

        }//If a PANA packet is received
        
	//ending while(!signal_received)
		pana_debug("Exits the client's main while loop");
		/* 
		 * When the client's program is gonna exit, the current state 
		 * must be checked. In case the state is OPEN, the client must 
		 * finish communications with the PANA server. Otherwise it can 
		 * simply free the memory used and exit.
		 */
        if (pana_session.CURRENT_STATE == OPEN) {
			//Set the pac state machine to terminate
            pana_session.TERMINATE = 1;
            pthread_mutex_lock(&session_mutex);
            transition(&pana_session); //Transition to make it effective
            pthread_mutex_unlock(&session_mutex);
            pana_debug("Has to tell the server that he's gonna stop");
			//It will manage pana messages until client disconnects
            while (TRUE){

				if (IP_VERSION==4)
					addr_size = sizeof (eap_auth_ll_addr);
				else if (IP_VERSION==6)
					addr_size = sizeof (eap_auth_ll_addr6);
				FD_ZERO(&readfds); //Setting to 0 FDsets
				FD_ZERO(&exceptfds);
				FD_SET(pana_sock, &readfds); //Assigning the FDs to pana socket
				FD_SET(pana_sock, &exceptfds);
				
				pana_debug("I'm gonna start listening!");
				pana_debug("My state is: %s", state_name[pana_session.CURRENT_STATE + 1]);
				
				//Wait for net events
				if (select(FD_SETSIZE, &readfds, NULL, &exceptfds, NULL) < 0) {
					perror("select");
					break;
				}

				//If a PANA packet is received
				if (FD_ISSET(pana_sock, &readfds)) {
					uint16_t length =0;
					if (IP_VERSION==4)
						length = recvfrom(pana_sock, pana_packet, sizeof (pana_packet), 0, (struct sockaddr *) &eap_auth_ll_addr, (socklen_t *) & addr_size);
					else if (IP_VERSION==6)
						length = recvfrom(pana_sock, pana_packet, sizeof (pana_packet), 0, (struct sockaddr *) &eap_auth_ll_addr, (socklen_t *) & addr_size);
					//length is >0 when it's correctly received only
					if (length > 0) {

						updateSession(pana_packet, &pana_session);
						pana_debug("My state to begin a transition is: %s", state_name[pana_session.CURRENT_STATE + 1]);
						pthread_mutex_lock(&session_mutex);
						transition(&pana_session);
						pthread_mutex_unlock(&session_mutex);
					}
				}
			}//While(TRUE)  to finish pana communications
        }//If current_state == OPEN
        else{ //Current_state != OPEN
			//Free memory used
			//fprintf(stderr,"DEBUG: maincliente.c");
			disconnect();
		}

}
