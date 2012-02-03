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
			else if (strcmp((char *)cur_node->name, "IP")==0){  // IP configurable value
				if (paa){

					xmlChar * value = xmlNodeGetContent(cur_node);
					DESTIP = XMALLOC(char,strlen((char*)value));
					sprintf(DESTIP, "%s",(char *) value);
					xmlFree(value);
				}
				else if (pac) {
					xmlChar * value = xmlNodeGetContent(cur_node);
					LOCALIP = XMALLOC(char,strlen((char*)value));
					sprintf(LOCALIP, "%s", (char *)value);
					xmlFree (value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PORT")==0){ // Port configurable value
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%hd", &DSTPORT);
					xmlFree(value);
					//This checking is avoided to let us use whichever port
					/*if (DSTPORT != 716){
						pana_error("PAA Port must be set to 716");
						checkconfig = TRUE;
					}*/
				}
				else if (pac) {
					
					xmlChar * value = xmlNodeGetContent(cur_node);
					sscanf((char *) value, "%hd", &SRCPORT);
					xmlFree(value);
					if (SRCPORT <=1024){
						pana_error("PaC Port must be set to a number higher than 1024.");
						checkconfig = TRUE;
					}
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
					sscanf(value, "%d", &PRF_HMAC_SHA1);
					xmlFree(value);
					if (PRF_HMAC_SHA1 <=0 || PRF_HMAC_SHA1 > 4){
						pana_error("PaC PRF algorithm must be set to a number between 1 and 4");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "INTEGRITY")==0){ // Integrity algorithm configurable value
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value , "%d", &AUTH_HMAC_SHA1_160);
					xmlFree(value);
					if (AUTH_HMAC_SHA1_160 <=0 || AUTH_HMAC_SHA1_160 > 7){
						pana_error("PaC Integrity algorithm must be set to a number between 1 and 7");
						checkconfig = TRUE;
					}
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
					sscanf(value, "%d", &PRF_HMAC_SHA1);
					xmlFree(value);
					if (PRF_HMAC_SHA1 <=0 || PRF_HMAC_SHA1 > 4){
						pana_error("PAA PRF algorithm must be set to a number between 1 and 4");
						checkconfig = TRUE;
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "INTEGRITY")==0){ // Integrity algorithm configurable value
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &AUTH_HMAC_SHA1_160);
					xmlFree(value);
					if (AUTH_HMAC_SHA1_160 <=0 || AUTH_HMAC_SHA1_160 > 7){
						pana_error("PAA Integrity algorithm must be set to a number between 1 and 7");
						checkconfig = TRUE;
					}
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
		pana_warning("Loading config.xml from current directory");
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
		pana_warning("Loading config.xml from current directory");
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
