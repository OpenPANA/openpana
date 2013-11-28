/**
 * @file mainpre.c
 * @brief  PRE's main program.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez on 30/04/12.
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

#include <signal.h>
#include <errno.h>

#include "mainpre.h"
#include "loadconfig.h"
#include "panamessages.h"
#include "panautils.h"

//Global variables
static bool fin = FALSE;



void signal_handler(int sig) {
    printf("\nStopping server, signal: %d\n", sig);
    fin = TRUE;
}


int main(int argc, char *argv[]) {

	printf("\n%s Relay - %s",PACKAGE_NAME,PACKAGE_VERSION);
	printf("\n%s\n\n",PACKAGE_URL);
    printf("Copyright (C) 2011  Pedro Moreno Sánchez and Francisco Vidal Meca\n");
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions, see COPYING for details.\n\n");

    //Load the configuration
    load_config_pre();

	/////Init the main loop/////

	//To handle exit signals
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

	//To handle the reception of messages
    int pac_sock=0; //Listening to PaC messages
    int paa_sock=0; //Listening to PAA messages
    struct sockaddr_in sa_pac;
    struct sockaddr_in sa_paa;
    struct sockaddr_in6 sa6_pac;
    struct sockaddr_in6 sa6_paa;
    fd_set mreadset; /*master read set*/

	if (IP_VERSION==4){
		pac_sock = socket(AF_INET, SOCK_DGRAM, 0);
		paa_sock = socket(AF_INET, SOCK_DGRAM, 0);
	}
	else if (IP_VERSION==6){
		pac_sock = socket(AF_INET6, SOCK_DGRAM, 0);
		paa_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	}
	
    int b = 1;
    // SO_REUSEADDR option is used in case of an unexpected exit, the
    // pre will be able to reuse the sockets
    if (setsockopt(pac_sock, SOL_SOCKET, SO_REUSEADDR, &b, 4)) {
        perror("setsockopt");
        return 0;
    }

    if (setsockopt(paa_sock, SOL_SOCKET, SO_REUSEADDR, &b, 4)) {
        perror("setsockopt");
        return 0;
    }

	//Sockets initialization
    if (IP_VERSION==4){
		//PaC socket initialization
		memset((char *) & sa_pac, 0, sizeof (sa_pac));
		sa_pac.sin_family = AF_INET;
		sa_pac.sin_port = htons(PORT_LISTEN_PAC);
		sa_pac.sin_addr.s_addr = htonl(INADDR_ANY);
		
		//Avoid's a warning, bind expects the "const ptr" type
		const struct sockaddr * sockaddr_pac = (struct sockaddr *) & sa_pac;
		if (bind(pac_sock, sockaddr_pac, sizeof (sa_pac)) == -1) {
			perror("Binding socket error:\n");
			return 1;
		}

		//PAA socket initialization
		memset((char *) & sa_paa, 0, sizeof (sa_paa));
		sa_paa.sin_family = AF_INET;
		sa_paa.sin_port = htons(PORT_LISTEN_PAA);
		sa_paa.sin_addr.s_addr = htonl(INADDR_ANY);
		
		//Avoid's a warning, bind expects the "const ptr" type
		const struct sockaddr * sockaddr_paa = (struct sockaddr *) & sa_paa;
		if (bind(paa_sock, sockaddr_paa, sizeof (sa_paa)) == -1) {
			perror("Binding socket error:\n");
			return 1;
		}
	}
	else if (IP_VERSION==6){
		//PaC socket initialization
		memset((char *) & sa6_pac, 0, sizeof (sa6_pac));
		sa6_pac.sin6_family = AF_INET6;
		sa6_pac.sin6_port = htons(PORT_LISTEN_PAC);
		sa6_pac.sin6_addr = in6addr_any;
		
		//Avoid's a warning, bind expects the "const ptr" type
		const struct sockaddr * sockaddr_pac = (struct sockaddr *) & sa6_pac;
		if (bind(pac_sock, sockaddr_pac, sizeof (sa6_pac)) == -1) {
			perror("Binding socket error:\n");
			return 1;
		}

		//PAA socket initialization
		memset((char *) & sa6_paa, 0, sizeof (sa6_paa));
		sa6_paa.sin6_family = AF_INET6;
		sa6_paa.sin6_port = htons(PORT_LISTEN_PAA);
		sa6_paa.sin6_addr = in6addr_any;
		
		//Avoid's a warning, bind expects the "const ptr" type
		const struct sockaddr * sockaddr_paa = (struct sockaddr *) & sa6_paa;
		if (bind(paa_sock, sockaddr_paa, sizeof (sa6_paa)) == -1) {
			perror("Binding socket error:\n");
			return 1;
		}
	}

    unsigned char udp_packet[MAX_DATA_LEN];
    struct sockaddr_in paa_dst_addr, pac_dst_addr;
    struct sockaddr_in6 paa_dst_addr6, pac_dst_addr6; //For ipv6 support
    int addr_size;
    char * elmnt; //To extract the AVP from the message.
    
    int length;

    while (!fin) {
        FD_ZERO(&mreadset);
        FD_SET(pac_sock, &mreadset);
        FD_SET(paa_sock, &mreadset);

        printf("PANA: I'm gonna start listening..\n");
        int ret = select(paa_sock + 1, &mreadset, NULL, NULL, NULL);

        if (ret > 0) {
            //Check pana messages
            if (FD_ISSET(pac_sock, &mreadset)) { //If a message has been received from the PaC

				if (IP_VERSION==4) {
					addr_size = sizeof (pac_dst_addr);
					length = recvfrom(pac_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(pac_dst_addr), (socklen_t *)&(addr_size));

					//Set the PAA address to forward the message.
					memset(&(paa_dst_addr), 0, sizeof(struct sockaddr));
					paa_dst_addr.sin_family = AF_INET;
					paa_dst_addr.sin_addr.s_addr = inet_addr(IP_PAA);
					paa_dst_addr.sin_port = htons(PORT_PAA);

					if (length > 0) {
						printf("PANA: Received message from the PaC\n");
						//Here, a message has just been received from the PaC. This message needs to be relayed and sent to the PAA.
						transmissionRelayedMessage(IP_VERSION, &paa_dst_addr, udp_packet, paa_sock, &pac_dst_addr);
						printf("PANA: Sent a relayed message to the PAA\n");
					}
					else pana_error("recvfrom returned ret=%d, errno=%d", length, errno);
				}
				else if (IP_VERSION==6){
					addr_size = sizeof (pac_dst_addr6);
					length = recvfrom(pac_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(pac_dst_addr6), (socklen_t *)&(addr_size));

					//Set the PAA address to forward the message.
					memset(&(paa_dst_addr6), 0, sizeof(struct sockaddr));
					paa_dst_addr6.sin6_family = AF_INET6;
					inet_pton(AF_INET6, IP_PAA, &(paa_dst_addr6.sin6_addr));
					paa_dst_addr6.sin6_port = htons(PORT_PAA);

					if (length > 0) {
						printf("PANA: Received message from the PaC\n");
						//Here, a message has just been received from the PaC. This message needs to be relayed and sent to the PAA.
						transmissionRelayedMessage(IP_VERSION, &paa_dst_addr6, udp_packet, paa_sock, &pac_dst_addr6);
						printf("PANA: Sent a relayed message to the PAA\n");
					}
					else pana_error("recvfrom returned ret=%d, errno=%d", length, errno);
				}    
            }
            
            if (FD_ISSET(paa_sock, &mreadset)) {//If a message has been received from the PAA

				
				if (IP_VERSION==4){
					addr_size = sizeof (paa_dst_addr);
					length = recvfrom(paa_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(paa_dst_addr), (socklen_t *)&(addr_size));

					elmnt = getAvp(udp_packet, PACINFORMATION_AVP);//It is necessary to get the PaC information
					
					//It is needed to extract the PaC address to forward the message
					memset(&(pac_dst_addr), 0, sizeof(struct sockaddr_in));
					pac_dst_addr.sin_family = AF_INET;
					memcpy(&(pac_dst_addr.sin_addr), elmnt+sizeof(avp_pana), sizeof(struct in_addr));
					memcpy(&(pac_dst_addr.sin_port), (elmnt+sizeof(avp_pana)+sizeof(struct in_addr)), sizeof(short));

					if (length>0){
						printf("PANA: Received a relayed message from the PAA\n");
						debug_msg((pana*) udp_packet);
						elmnt = getAvp(udp_packet, RELAYEDMESSAGE_AVP);


						if (0 >= sendPana(pac_dst_addr, (elmnt+sizeof(avp_pana)), pac_sock)) {
							pana_fatal("sendPana");
						}
						printf("PANA: Sent a message to the PaC\n");
						debug_msg((pana*) (elmnt+sizeof(avp_pana)));
					}

				}
				else if (IP_VERSION==6){
					addr_size = sizeof (paa_dst_addr6);
					length = recvfrom(paa_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(paa_dst_addr6), (socklen_t *)&(addr_size));

					elmnt = getAvp(udp_packet, PACINFORMATION_AVP);//It is necessary to get the PaC information
					
					memset( &(pac_dst_addr6), 0, sizeof(struct sockaddr_in6));
					pac_dst_addr6.sin6_family = AF_INET6;
					memcpy (&(pac_dst_addr6.sin6_addr), (elmnt+sizeof(avp_pana)), sizeof (struct in6_addr));
					memcpy (&(pac_dst_addr6.sin6_port), (elmnt+sizeof(avp_pana)+sizeof(struct in6_addr)), sizeof(short));
					


					if (length>0){
						printf("PANA: Received a relayed message from the PAA\n");
						debug_msg ((pana*)udp_packet);
						elmnt = getAvp(udp_packet, RELAYEDMESSAGE_AVP);

						
						if (0 >= sendPana6(pac_dst_addr6, (elmnt+sizeof(avp_pana)), pac_sock)) {
							pana_fatal("sendPana");
						}
						printf("PANA: Sent a message to the PaC\n");
						debug_msg((pana*) (elmnt+sizeof(avp_pana)));
						
					}
				}

                
                else
					pana_error("recvfrom returned ret=%d, errno=%d", length, errno);
            }
        }
    }
}

