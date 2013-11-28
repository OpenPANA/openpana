/**
 * @file loadconfig.c
 * @brief  Contains functions wich performs the parser xml file for the
 * PaC and PAA.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 06/07/10.
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

#include "loadconfig.h"
#include "panautils.h"

int pac =0;
int paa =0;
int pre =0;


char * getInterfaceIPaddress (int ip_version, char* interface){
	char * address; //It will contain the address

	struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

	if (ip_version != 4 && ip_version!= 6 ){
		pana_error("getInterfaceIPaddress: the IP version must be IPv4 or IPv6");
		return NULL;
	}
	
    getifaddrs(&ifAddrStruct);

	if (ifAddrStruct==NULL){
		freeifaddrs(ifAddrStruct);
		pana_error("getInterfaceIPaddress: Unable of getting the interface information");
	 }

	
	if (ip_version==4) {
		for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
			if ((ifa ->ifa_addr->sa_family==AF_INET) && (strcmp(ifa->ifa_name, interface)==0)) { // check it is IP4 and it is the correct interface
				address = XMALLOC(char, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, address, INET_ADDRSTRLEN);
				
				return address;
			}
		}
	}

	else if (ip_version == 6) {
		for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
			if ((ifa ->ifa_addr->sa_family==AF_INET6) && (strcmp(ifa->ifa_name, interface)==0)) { // check it is IP4 and it is the correct interface
				address = XMALLOC(char, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, address, INET6_ADDRSTRLEN);

				return address;
			}
		}
	}

	return NULL;
}


/**
 * parse_xml_client:
 * @param a_node: the initial xml node to consider.
 *
 * Parse all the xml client elements
 * that are siblings or children of a given xml node.
 */
static void parse_xml_client(xmlNode * a_node) {
#ifdef ISCLIENT
    xmlNode *cur_node = NULL;
	int checkconfig = FALSE;
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp((char*) cur_node->name, "IP_VERSION")==0) {
				char * value = (char *)xmlNodeGetContent(cur_node);
				sscanf(value, "%d", &IP_VERSION);
				xmlFree(value);
				if (IP_VERSION != 4 && IP_VERSION != 6){
					pana_error("IP_VERSION must be set to 4 for IPv4 or to 6 for IPv6.");
					checkconfig = TRUE;
				}
			}
			else if (strcmp((char*) cur_node->name, "PAC")==0) { //If the PaC configurable values are being checked
				paa=0;
				pac=1;
			}
			else if (strcmp((char *)cur_node->name, "PAA")==0) { //If the PAA configurable values are being checked
				paa=1;
				pac=0;
			}
			else if (strcmp((char *)cur_node->name, "INTERFACE")==0){  // IP configurable value
				if (pac) {
					char * value = (char*)xmlNodeGetContent(cur_node);
					char * aux = getInterfaceIPaddress(IP_VERSION, value);
					if (aux == NULL) {
						pana_error("The interface where the PAC is going to listen incoming messages is not correct");
						checkconfig=TRUE;
					}
					else {
						LOCALIP = XMALLOC(char, strlen(aux));
						memcpy(LOCALIP, aux, strlen(aux));
						xmlFree(value);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "IP_PAA")==0){  // IP configurable value
				if (pac) {
					xmlChar * value = xmlNodeGetContent(cur_node);
					DESTIP = XMALLOC(char,strlen((char*)value));
					sprintf(DESTIP, "%s", (char *)value);
					xmlFree (value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PORT")==0){ // Port configurable value
				if (pac) {
					
					xmlChar * value = xmlNodeGetContent(cur_node);
					sscanf((char *) value, "%hd", &SRCPORT);
					xmlFree(value);
					if (SRCPORT <=1024){
						pana_error("PaC Port must be set to a number higher than 1024.");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "PORT_PAA")==0){ // Port configurable value
				if (pac) {
					
					xmlChar * value = xmlNodeGetContent(cur_node);
					sscanf((char *) value, "%hd", &DSTPORT);
					xmlFree(value);
					//This checking is avoided to let us use whichever port
					//if (DSTPORT != 716){
					//	pana_error("PAA Port must be set to 716");
					//	checkconfig = TRUE;
					//}
				}
			}
			else if (strcmp((char *)cur_node->name, "TIMEOUT")==0){ // Timeout configurable value
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &FAILED_SESS_TIMEOUT_CONFIG);
					xmlFree(value);
					if (FAILED_SESS_TIMEOUT_CONFIG <=0){ 
						pana_error("PaC Session Timeout must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "PRF")==0){ // PRF algorithm configurable value
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &PRF_SUITE);
					xmlFree(value);
					#ifdef AESCRYPTO
					if ((PRF_SUITE != 5) && (PRF_SUITE != 2)){
						pana_error("PaC PRF algorithm %d is not supported yet", PRF_SUITE);
						checkconfig = TRUE;
					}
					#else
					if (PRF_SUITE == 5){
						pana_error("PaC PRF algorithm based on AES is not compiled. You can compile the AES cryptographic suite (see INSTALL)");
						checkconfig = TRUE;
					}
					else if (PRF_SUITE != 2) {
						pana_error("PaC PRF algorithm %d is not supported yet", PRF_SUITE);
						checkconfig = TRUE;
					}
					#endif
				}
			}
			else if (strcmp((char *)cur_node->name, "INTEGRITY")==0){ // Integrity algorithm configurable value
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value , "%d", &AUTH_SUITE);
					xmlFree(value);
					#ifdef AESCRYPTO
					if ((AUTH_SUITE != 8) && (AUTH_SUITE != 7)){
						pana_error("PaC AUTH algorithm %d is no supported yet.", AUTH_SUITE);
						checkconfig = TRUE;
					}
					#else
					if (AUTH_SUITE == 8){
						pana_error("PaC AUTH algorithm based on AES is not compiled. You can compile the AES cryptographic suite (see INSTALL)");
						checkconfig = TRUE;
					}
					else if (AUTH_SUITE != 7) {
						pana_error("PaC AUTH algorithm %d is no supported yet.", AUTH_SUITE);
						checkconfig = TRUE;
					}
					#endif
				}
			}
			else if (strcmp((char *)cur_node->name, "USER")==0){ // User name configurable value
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					USER = XMALLOC(char,strlen((char*)value));
					sprintf(USER, "%s",(char *) value);
					xmlFree(value);
					
				}
			}
			else if (strcmp((char *)cur_node->name, "PASSWORD")==0){ // Password configurable value
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					PASSWORD = XMALLOC(char,strlen((char*)value));
					sprintf(PASSWORD, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "CA_CERT")==0){ // CA cert's name.
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					char * complete = XMALLOC(char,strlen((char*)value)+strlen(CONFIGDIR)+20);
					sprintf(complete,"%s/%s",CONFIGDIR,(char*)value);
					//Check if the file exists
					if( access( complete, F_OK ) == -1 ) {
						// file doesn't exist in config directory
						if( access( value, F_OK ) == -1 ) {
							//FIXME
							pana_error("CA Certificate \"%s\" needed to run doesn't exist",value);
							checkconfig = TRUE;
						}
						else{
							printf("PANA: Loading %s from current directory.\n",value);
							CA_CERT = XMALLOC(char,strlen((char*)value));
							sprintf(CA_CERT, "%s",(char *) value);
						}
					}
					else{
						printf("PANA: Loading %s from config directory.\n",value);
						CA_CERT = complete;
					}
					
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "CLIENT_CERT")==0){// Client certificate's name configurable value
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					
					char * complete = XMALLOC(char,strlen((char*)value)+strlen(CONFIGDIR)+20);
					sprintf(complete,"%s/%s",CONFIGDIR,(char*)value);
					//Check if the file exists
					if( access( complete, F_OK ) == -1 ) {
						// file doesn't exist in config directory
						if( access( value, F_OK ) == -1 ) {
							pana_error("Client's certificate \"%s\" needed to run doesn't exist",value);
							checkconfig = TRUE;
						}
						else{
							printf("PANA: Loading %s from current directory.\n",value);
							CLIENT_CERT = XMALLOC(char,strlen((char*)value));
							sprintf(CLIENT_CERT, "%s",(char *) value);
						}
					}
					else{
						printf("PANA: Loading %s from config directory.\n",value);
						CLIENT_CERT = complete;
					}
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "CLIENT_KEY")==0){// Client key certificate's name configurable value
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					char * complete = XMALLOC(char,strlen((char*)value)+strlen(CONFIGDIR)+20);
					sprintf(complete,"%s/%s",CONFIGDIR,(char*)value);
					//Check if the file exists
					if( access( complete, F_OK ) == -1 ) {
						// file doesn't exist in config directory
						if( access( value, F_OK ) == -1 ) {
							pana_error("Client's key file \"%s\" needed to run doesn't exist",value);
							checkconfig = TRUE;
						}
						else{
							printf("PANA: Loading %s from current directory.\n",value);
							CLIENT_KEY = XMALLOC(char,strlen((char*)value));
							sprintf(CLIENT_KEY, "%s",(char *) value);
						}
					}
					else{
						printf("PANA: Loading %s from config directory.\n",value);
						CLIENT_KEY = complete;
					}
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PRIVATE_KEY")==0){ // Client private key value
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					PRIVATE_KEY = XMALLOC(char,strlen((char*)value));
					sprintf(PRIVATE_KEY, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "FRAGMENT_SIZE")==0){// Size of EAP fragments.
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &FRAG_SIZE);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PING_TIME")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &PING_TIME);
					xmlFree(value);
					if (PING_TIME<=0){
						pana_error("The delay to do the ping exchanges must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "NUMBER_PING")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &NUMBER_PING);
					sscanf(value, "%d", &NUMBER_PING_AUX);
					xmlFree(value);
					if (NUMBER_PING <0 ){
						pana_error("The number of ping messages to be exchanged must be set to 0 (to be desactivated) or to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
#ifdef ISCLIENT
			else if (strcmp((char *)cur_node->name, "EAP_PIGGYBACK")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &EAP_PIGGYBACK);
					xmlFree(value);
					if ((EAP_PIGGYBACK < 0) || (EAP_PIGGYBACK > 1)){
						pana_error("The eap piggyback option must be set to 1 (activated) or to 0 (not activated)");
						checkconfig = TRUE;
					}
				}
			}
#endif
        }

        parse_xml_client(cur_node->children);
    }
    
    if(checkconfig){
		pana_fatal("Check configuration to continue");
	}
#endif
}


/**
 * parse_xml_server:
 * @a_node: the initial xml node to consider.
 *
 * Parse all the xml server elements
 * that are siblings or children of a given xml node.
 */

static void parse_xml_server(xmlNode * a_node){
#ifdef ISSERVER
    xmlNode *cur_node = a_node;
	int checkconfig = FALSE;
	
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp((char*) cur_node->name, "IP_VERSION")==0) {
				char * value = (char *)xmlNodeGetContent(cur_node);
				sscanf(value, "%d", &IP_VERSION);
				xmlFree(value);
				if (IP_VERSION != 4 && IP_VERSION != 6){
					pana_error("IP_VERSION must be set to 4 for IPv4 or to 6 for IPv6");
					checkconfig = TRUE;
				}
			}
			else if (strcmp((char *)cur_node->name, "PAC")==0) {//If the PaC configurable values are being checked
				paa=0;
				pac=1;
			}
			else if (strcmp((char *)cur_node->name, "PAA")==0) {//If the PAA configurable values are being checked
				paa=1;
				pac=0;
			}
			else if (strcmp((char *)cur_node->name, "INTERFACE")==0){  // IP configurable value
				if (paa) {
					char * value = (char*)xmlNodeGetContent(cur_node);
					char * aux = getInterfaceIPaddress(IP_VERSION, value);
					if (aux == NULL) {
						pana_error("The interface where the PAA is going to listen to PAC incoming messages is not correct");
						checkconfig=TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "PORT")==0){ // Port configurable value
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &SRCPORT);
					xmlFree(value);
					//This checking is avoided to let us use whichever port
					/*if (SRCPORT != 716){
						pana_error("PAA Port must be set to 716");
						checkconfig = TRUE;
					}*/
				}
			}
			else if (strcmp((char *)cur_node->name, "TIMEOUT")==0){ // Timeout configurable value
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &LIFETIME_SESSION_TIMEOUT_CONFIG);
					xmlFree(value);
					if (LIFETIME_SESSION_TIMEOUT_CONFIG <=0){
						pana_error("PAA Session Timeout must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "PRF")==0){// PRF algorithm configurable value
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &PRF_SUITE);
					xmlFree(value);
					#ifdef AESCRYPTO
					if ((PRF_SUITE != 5) && (PRF_SUITE != 2)){
						pana_error("PAA PRF algorithm %d is not supported", PRF_SUITE);
						checkconfig = TRUE;
					}
					#else
					if (PRF_SUITE == 5){
						pana_error("PAA PRF algorithm based on AES is not compiled. You can compile the AES cryptographic suite (see INSTALL)");
						checkconfig = TRUE;
					}
					else if (PRF_SUITE != 2) {
						pana_error("PAA PRF algorithm %d is not supported", PRF_SUITE);
						checkconfig = TRUE;
					}
					#endif
				}
			}
			else if (strcmp((char *)cur_node->name, "INTEGRITY")==0){ // Integrity algorithm configurable value
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &AUTH_SUITE);
					xmlFree(value);
					#ifdef AESCRYPTO
					if ((AUTH_SUITE != 8) && (AUTH_SUITE != 7)){
						pana_error("PAA AUTH algorithm %d is not suppported yet", AUTH_SUITE);
						checkconfig = TRUE;
					}
					#else
					if (AUTH_SUITE == 8){
						pana_error("PAA AUTH algorithm based on AES is not compiled. You can compile the AES cryptographic suite (see INSTALL)");
						checkconfig = TRUE;
					}
					else if (AUTH_SUITE != 7){
						pana_error("PAA AUTH algorithm %d is not suppported yet", AUTH_SUITE);
						checkconfig = TRUE;
					}
					#endif
				}
			}
			else if (strcmp((char *)cur_node->name, "TIMEOUT_CLIENT")==0){ // Timeout for client's session.
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG);
					xmlFree(value);
					if (LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG <=0){
						pana_error("PAA TIMEOUT CLIENT must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "WORKERS")==0){ // Number of workers to be executed.
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &NUM_WORKERS);
					xmlFree(value);
					if (NUM_WORKERS <=0){
						pana_error("The worker's number must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			
			else if (strcmp((char *)cur_node->name, "TIME_ANSWER")==0){ // Timeout without a response to the first PANA request message.
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &TIME_PCI);
					xmlFree(value);
					if (TIME_PCI <=0){
						pana_error("The answer's time must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "CA_CERT")==0){ // CA cert's name.
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					CA_CERT = XMALLOC(char,strlen((char*)value));
					sprintf(CA_CERT, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "SERVER_CERT")==0){ // Server certificate's name
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					SERVER_CERT = XMALLOC(char,strlen((char*)value));
					sprintf(SERVER_CERT, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "SERVER_KEY")==0){ // Server key certificate's name
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					SERVER_KEY = XMALLOC(char,strlen((char*)value));
					sprintf(SERVER_KEY, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "IP_VERSION_AUTH")==0){ // IP address of AS
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &IP_VERSION_AUTH);
					xmlFree(value);
					if ((IP_VERSION_AUTH != 4) && (IP_VERSION_AUTH != 6) ){
						pana_error("IP_VERSION_AUTH must be set to 4 for IPv4 or to 6 for IPv6.");
						checkconfig = TRUE;
					}
				}

				
			}
			else if (strcmp((char *)cur_node->name, "AS_IP")==0){ // IP address of AS
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					AS_IP = XMALLOC(char,strlen((char*)value));
					sprintf(AS_IP, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "AS_PORT")==0){ // Port value for communication with the AS.
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%hd", &AS_PORT);
					xmlFree(value);
					if (AS_PORT <= 0){
						pana_error("The Authentication Server's Port must be higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "SHARED_SECRET")==0){ // Shared secret between EAP auth & EAP server.
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					AS_SECRET = XMALLOC(char,strlen((char*)value));
					sprintf(AS_SECRET, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PING_TIME")==0){
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &PING_TIME);
					xmlFree(value);
					if (PING_TIME<=0){
						pana_error("The delay to do the ping exchanges must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "NUMBER_PING")==0){
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &NUMBER_PING);
					sscanf(value, "%d", &NUMBER_PING_AUX);
					xmlFree(value);
					if (NUMBER_PING <0 ){
						pana_error("The number of ping messages to be exchanged must be set to 0 (to be desactivated) or to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
        }

        parse_xml_server(cur_node->children);
    }
    if(checkconfig){
		pana_fatal("Check configuration to continue");
	}
#endif
}


/**
 * parse_xml_pre:
 * @param a_node: the initial xml node to consider.
 *
 * Parse all the xml pre elements
 * that are siblings or children of a given xml node.
 */
static void parse_xml_pre(xmlNode * a_node) {

    xmlNode *cur_node = NULL;
	int checkconfig = FALSE;
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp((char*) cur_node->name, "IP_VERSION")==0) {
				char * value = (char *)xmlNodeGetContent(cur_node);
				sscanf(value, "%d", &IP_VERSION);
				xmlFree(value);
				if (IP_VERSION != 4 && IP_VERSION != 6){
					pana_error("IP_VERSION must be set to 4 for IPv4 or to 6 for IPv6.");
					checkconfig = TRUE;
				}
			}
			else if (strcmp((char*) cur_node->name, "PAC")==0) { //If the PaC configurable values are being checked
				paa=0;
				pac=1;
				pre=0;
			}
			else if (strcmp((char *)cur_node->name, "PAA")==0) { //If the PAA configurable values are being checked
				paa=1;
				pac=0;
				pre=0;
			}
			else if (strcmp((char *)cur_node->name, "PRE")==0) { //If the PAA configurable values are being checked
				paa=0;
				pac=0;
				pre=1;
			}
			else if (strcmp((char *)cur_node->name, "IP_PAA")==0){  // IP configurable value
				if (pre){

					xmlChar * value = xmlNodeGetContent(cur_node);
					IP_PAA = XMALLOC(char,strlen((char*)value));
					sprintf(IP_PAA, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PORT_PAA")==0){ // Port configurable value
				if (pre){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%hd", &PORT_PAA);
					xmlFree(value);

					if (PORT_PAA <=0) {
						pana_error("The PAA Port must be set to a number higher than 0");
						checkconfig = TRUE;
					}
				}
			}
			
			else if (strcmp((char *)cur_node->name, "INTERFACE_PAC")==0){
				char * value = (char*)xmlNodeGetContent(cur_node);
				char * aux = getInterfaceIPaddress(IP_VERSION, value);
				if (aux == NULL) {
					pana_error("The interface where the PRE is going to listen to PAC incoming messages is not correct");
					checkconfig=TRUE;
				}
				else {
					IP_LISTEN_PAC = XMALLOC(char, strlen(aux));
					memcpy(IP_LISTEN_PAC, aux, strlen(aux));
					xmlFree(value);
				}
			}

			else if (strcmp((char *)cur_node->name, "PORT_PAC")==0){
				char * value = (char *)xmlNodeGetContent(cur_node);
				sscanf(value, "%hd", &PORT_LISTEN_PAC);
				xmlFree(value);

				if (PORT_LISTEN_PAC <=0) {
					pana_error("The port where the PRE will listen to incoming PAC messages must be set to a number higher than 0");
					checkconfig=TRUE;
				}
			}
			
			else if (strcmp((char *)cur_node->name, "INTERFACE_PAA")==0){
				char * value = (char*)xmlNodeGetContent(cur_node);
				char * aux = getInterfaceIPaddress(IP_VERSION, value);
				if (aux == NULL) {
					pana_error("The interface where the PRE is going to listen to PAA incoming messages is not correct");
					checkconfig=TRUE;
				}
				else {
					IP_LISTEN_PAA = XMALLOC(char, strlen(aux));
					memcpy(IP_LISTEN_PAA, aux, strlen(aux));
					xmlFree(value);
				}
			}

			else if (strcmp((char *)cur_node->name, "PORT_PAA")==0){
				char * value = (char *)xmlNodeGetContent(cur_node);
				sscanf(value, "%hd", &PORT_LISTEN_PAA);
				xmlFree(value);

				if (PORT_LISTEN_PAA <=0) {
					pana_error("The port where the PRE will listen to incoming PAA messages must be set to a number higher than 0");
					checkconfig=TRUE;
				}
			}
        }

        parse_xml_pre(cur_node->children);
    }
    
    if(checkconfig){
		pana_fatal("Check configuration to continue");
	}

}


/**
 * Parse configurable values from client context
 */
int
load_config_client()
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
	//First check if CONFIGDIR"/config.xml" exists
	if( access( CONFIGDIR"/config.xml", F_OK ) != -1 ) {
		// file exists and it can be opened
		doc = xmlReadFile(CONFIGDIR"/config.xml", NULL, 0);
	} else {
		// file doesn't exist
		//pana_warning("Loading config.xml from current directory");
		doc = xmlReadFile("config.xml", NULL, 0);
	}
 	
	if(doc==NULL){
		pana_fatal("Could not parse file config.xml. \nThe application can't run without this file");
	}

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    parse_xml_client(root_element);

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return 0;
}


/**
 * Parse configurable values from server context
 */
int
load_config_server()
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
        

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
	//First check if CONFIGDIR"/config.xml" exists
	if( access( CONFIGDIR"/config.xml", F_OK ) != -1 ) {
		// file exists and it can be opened
		doc = xmlReadFile(CONFIGDIR"/config.xml", NULL, 0);
	} else {
		// file doesn't exist
		//pana_warning("Loading config.xml from current directory");
		doc = xmlReadFile("config.xml", NULL, 0);
	}
 	
	if(doc==NULL){
		pana_fatal("Could not parse file config.xml. \nThe application can't run without this file" );
	}
 
    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    parse_xml_server(root_element);

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return 0;
}


/**
 * Parse configurable values from PANA Relay context
 */
int
load_config_pre()
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
	//First check if CONFIGDIR"/config.xml" exists
	if( access( CONFIGDIR"/config.xml", F_OK ) != -1 ) {
		// file exists and it can be opened
		doc = xmlReadFile(CONFIGDIR"/config.xml", NULL, 0);
	} else {
		// file doesn't exist
		//pana_warning("Loading config.xml from current directory");
		doc = xmlReadFile("config.xml", NULL, 0);
	}
 	
	if(doc==NULL){
		pana_fatal("Could not parse file config.xml. \nThe application can't run without this file");
	}

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    parse_xml_pre(root_element);

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return 0;
}
