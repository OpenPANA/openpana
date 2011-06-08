/*
 *  maincliente.c
 *  
 *
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

#include <stdio.h>
#include <stdlib.h> //Función exit
#include <unistd.h> //Function sleep
#include <pthread.h>     /* pthread functions and data structures     */
#include <arpa/inet.h>
#include <config.h>

#include "state_machines/statemachine.h"
#include "panamessages.h"
#include "state_machines/pacmachine.h"
#include "panautils.h"
#include "state_machines/session.h"
#include "./libeapstack/eap_peer_interface.h"
#include "maincliente.h"
#include "lalarm.h"


static int signal_received = FALSE;
struct lalarm* list_alarms = NULL; // alarms' list
pthread_mutex_t alarm_list_mutex;
pthread_mutex_t session_mutex;
pana_ctx pana_session;

void signal_handler(int sig) {
	#ifdef DEBUG
    fprintf(stderr,"\nDEBUG: Petición de salida del cliente, signal: %d\n", sig);
    #endif
    signal_received = TRUE;
}

void* handle_alarm_management(void* none) {

    while (1){
		
		struct timeval tv;
		gettimeofday(&tv,NULL);
		struct lalarm* alarm = NULL;
		while ((alarm=get_next_alarm(&list_alarms, tv.tv_sec)) != NULL){
			 if (alarm->id == RETR_ALARM) {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: Se ha producido una alarma de RETRANSMISIÓN_PANA\n");
	#endif
				
				pthread_mutex_lock(&session_mutex);
				alarm->pana_session->RTX_TIMEOUT = 1;
				transition(alarm->pana_session);
				pthread_mutex_unlock(&session_mutex);
			} else if (alarm->id == SESS_ALARM) {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: Se ha producido una alarma de SESIÓN\n");
	#endif
				
				pthread_mutex_lock(&session_mutex);
				alarm->pana_session->REAUTH = 1;
				eapRestart();
				transition(alarm->pana_session);
				pthread_mutex_unlock(&session_mutex);
			}
			else {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: Se ha producido una alarma de TIPO DESCONOCIDO\n");
	#endif
			}
		}
		usleep(TIME_WAKE_UP);
	}
}

int main(int argc, char *argv[]) {

    struct sockaddr_in eap_peer_ll_sockaddr, eap_auth_ll_sockaddr;
    fd_set readfds, exceptfds; //FD sets to use with select
    int pana_sock;//PANA's socket
	
#ifdef DEBUG
	//Array to show PANA state's names while debugging
    char * state_name[] = {"NO CHANGE", "INITIAL", "WAIT_PNA_PING",
        "CLOSED", "WAIT_PAA", "WAIT_EAP_MSG",
        "WAIT_EAP_RESULT", "WAIT_EAP_RESULT_CLOSE",
        "OPEN", "WAIT_PNA_REAUTH", "SESS_TERM",
        "WAIT_PAN_OR_PAR", "WAIT_FAIL_PAN",
        "WAIT_SUCC_PAN"};
#endif	
	printf("\n");
	printf(PACKAGE_NAME);
	printf(" Client - ");
	printf(PACKAGE_VERSION);
	printf("\n");
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
    
    list_alarms = crear_alarma(&alarm_list_mutex);
	pana_session.list_of_alarms = &(list_alarms);
	pthread_create(&alarm_thread, NULL, handle_alarm_management, NULL);

	//To handle exit signals
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    if ((pana_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    int b = 1;
    // Se le pone la opcion reuseaddr por si se cierra inesperadamente
    // el cliente que se pueda reutilizar el socket
    if (setsockopt(pana_sock, SOL_SOCKET, SO_REUSEADDR, &b, 4)) {
        perror("setsockopt");
        return 0;
    }
    //Evitaría que no se pudieran reutilizar puertos por una salida errónea
    
    memset((char *) &eap_peer_ll_sockaddr, 0, sizeof (eap_peer_ll_sockaddr));
    eap_peer_ll_sockaddr.sin_family = AF_INET;
    eap_peer_ll_sockaddr.sin_port = htons(pana_session.src_port);
    eap_peer_ll_sockaddr.sin_addr.s_addr = inet_addr(DESTIP); // FIXME: Esto xk no va del fich. de conf??

	//Avoid's a warning, bind expects the "const ptr" type
    const struct sockaddr * ll_sockaddr = (struct sockaddr *) &eap_peer_ll_sockaddr;
    if (bind(pana_sock, ll_sockaddr, sizeof (eap_peer_ll_sockaddr)) == -1) {
        perror("socket");
        return -1;
    }

	//Update the socket number in the session.
	pana_session.socket = pana_sock;
	
    eap_auth_ll_sockaddr.sin_family = AF_INET;
    eap_auth_ll_sockaddr.sin_port = pana_session.eap_ll_dst_addr.sin_port;
    inet_pton(AF_INET, LOCALIP, &eap_auth_ll_sockaddr.sin_addr);

    //Step pana state machine
    pthread_mutex_lock(&session_mutex);
    transition(&pana_session);
    pthread_mutex_unlock(&session_mutex);

	struct sockaddr_in eap_auth_ll_addr;
	int addr_size=0;
	u8 pana_packet[MAX_DATA_LEN];
	
	//Until a termination signal is received, the client must be working
    while (!signal_received) { 
		addr_size=0;
        
        FD_ZERO(&readfds); //Setting to 0 FDsets
        FD_ZERO(&exceptfds);
        FD_SET(pana_sock, &readfds); //Assigning the FDs to pana socket
        FD_SET(pana_sock, &exceptfds);
        
        addr_size = sizeof (eap_auth_ll_addr);
        
#ifdef DEBUG
        fprintf(stderr,"DEBUG: Me voy a poner a escuchar!\n");
        fprintf(stderr,"DEBUG: Mi estado es: %s\n", state_name[pana_session.CURRENT_STATE + 1]);
#endif
		//Wait for net events
        if (select(FD_SETSIZE, &readfds, NULL, &exceptfds, NULL) < 0) {
            perror("select");
            break;
        }

		//If a PANA packet is received
        if (FD_ISSET(pana_sock, &readfds)) {
            int length =0;
            length = recvfrom(pana_sock, pana_packet, sizeof (pana_packet), 0, (struct sockaddr *) &eap_auth_ll_addr, (socklen_t *) & addr_size);
			//length is >0 when it's correctly received only
            if (length > 0) {

                panaMessage *pana = NULL;
                pana = unserializePana((char *) pana_packet, length);
                pthread_mutex_lock(&session_mutex);
                updateSession(pana, &pana_session);
                pthread_mutex_unlock(&session_mutex);
#ifdef DEBUG
                fprintf(stderr,"DEBUG: Mi estado para realizar la transición es: %s\n", state_name[pana_session.CURRENT_STATE + 1]);
#endif
				pthread_mutex_lock(&session_mutex);
                transition(&pana_session);
                pthread_mutex_unlock(&session_mutex);
            }
            
                //Check if exist a Response for eap server
                if (eap_peer_get_eapResp(&(pana_session.eap_ctx)) == TRUE) {
#ifdef DEBUG
                    fprintf(stderr,"DEBUG: Hay un EAPResponse\n");
#endif
                    pthread_mutex_lock(&session_mutex);
                    transition(&pana_session);
                    pthread_mutex_unlock(&session_mutex);

                }

                //Check if eap authentication has finished with success
                if (eap_peer_get_eapSuccess(&(current_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
                    fprintf(stderr,"DEBUG: Hay un eapSuccess\n");
#endif
                    pthread_mutex_lock(&session_mutex);
                    transition(&pana_session);
                    pthread_mutex_unlock(&session_mutex);
                }
            }//length >0

        }//If a PANA packet is received
        
	//ending while(!signal_received)
#ifdef DEBUG
        fprintf(stderr, "DEBUG: Sale del bucle while principal cliente\n");
#endif
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
#ifdef DEBUG
            fprintf(stderr, "DEBUG: Debe comunicar al servidor que va a terminar.\n");
#endif
			//It will manage pana messages until client disconnects
            while (TRUE){
				
				addr_size = sizeof (eap_auth_ll_addr);
				FD_ZERO(&readfds); //Setting to 0 FDsets
				FD_ZERO(&exceptfds);
				FD_SET(pana_sock, &readfds); //Assigning the FDs to pana socket
				FD_SET(pana_sock, &exceptfds);
				
			#ifdef DEBUG
				fprintf(stderr,"DEBUG: Me voy a poner a escuchar!\n");
				fprintf(stderr,"DEBUG: Mi estado es: %s\n", state_name[pana_session.CURRENT_STATE + 1]);
			#endif
				//Wait for net events
				if (select(FD_SETSIZE, &readfds, NULL, &exceptfds, NULL) < 0) {
					perror("select");
					break;
				}

				//If a PANA packet is received
				if (FD_ISSET(pana_sock, &readfds)) {
					int length =0;
					length = recvfrom(pana_sock, pana_packet, sizeof (pana_packet), 0, (struct sockaddr *) &eap_auth_ll_addr, (socklen_t *) & addr_size);
					//length is >0 when it's correctly received only
					if (length > 0) {

						panaMessage *pana = NULL;
						pana = unserializePana((char *) pana_packet, length);
						updateSession(pana, &pana_session);
			#ifdef DEBUG
						fprintf(stderr,"DEBUG: Mi estado para realizar la transición es: %s\n", state_name[pana_session.CURRENT_STATE + 1]);
			#endif
						pthread_mutex_lock(&session_mutex);
						transition(&pana_session);
						pthread_mutex_unlock(&session_mutex);
					}
				}
			}//While(TRUE)  to finish pana communications
        }//If current_state == OPEN
        else{ //Current_state != OPEN
			//Free memory used
			disconnect();
		}

}
