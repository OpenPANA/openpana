/*
 *  loadconfig.c
 *  
 * 	Contains functions wich performs the parser xml file for the PaC and PAA.
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "loadconfig.h"

#ifdef LIBXML_TREE_ENABLED

/**
 * parse_xml_client:
 * @a_node: the initial xml node to consider.
 *
 * Parse all the xml client elements
 * that are siblings or children of a given xml node.
 */

int pac =0;
int paa =0;

static void
parse_xml_client(xmlNode * a_node)
{
#ifdef ISCLIENT
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp((char*) cur_node->name, "PAC")==0) {
				paa=0;
				pac=1;
			}
			else if (strcmp((char *)cur_node->name, "PAA")==0) {
				paa=1;
				pac=0;
			}
			else if (strcmp((char *)cur_node->name, "IP")==0){
				if (paa){

					xmlChar * value = xmlNodeGetContent(cur_node);
					DESTIP = malloc(strlen(value)*sizeof(char));
					sprintf(DESTIP, "%s",(char *) value);
					xmlFree(value);
				}
				else if (pac) {
					xmlChar * value = xmlNodeGetContent(cur_node);
					LOCALIP = malloc(strlen(value)*sizeof(char));
					sprintf(LOCALIP, "%s", (char *)value);
					xmlFree (value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PORT")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%hd", &DSTPORT);
					xmlFree(value);
					if (DSTPORT != 716){
						fprintf(stderr, "ERROR: PAA Port must be set to 716.\n");
						exit(1);
					}
				}
				else if (pac) {
					
					xmlChar * value = xmlNodeGetContent(cur_node);
					sscanf((char *) value, "%hd", &SRCPORT);
					xmlFree(value);
					if (SRCPORT <=1024){
						fprintf(stderr, "ERROR: PaC Port must be set to a number higher than 1024.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "TIMEOUT")==0){
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &FAILED_SESS_TIMEOUT_CONFIG);
					xmlFree(value);
					if (FAILED_SESS_TIMEOUT_CONFIG <=0){
						fprintf(stderr, "ERROR: PaC Session Timeout must be set to a number higher than 0.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "PRF")==0){
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &PRF_HMAC_SHA1);
					xmlFree(value);
					if (PRF_HMAC_SHA1 <=0 || PRF_HMAC_SHA1 > 4){
						fprintf(stderr, "ERROR: PaC PRF algorithm must be set to a number between 1 and 4.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "INTEGRITY")==0){
				if (pac) {
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value , "%d", &AUTH_HMAC_SHA1_160);
					xmlFree(value);
					if (AUTH_HMAC_SHA1_160 <=0 || AUTH_HMAC_SHA1_160 > 7){
						fprintf(stderr, "ERROR: PaC Integrity algorithm must be set to a number between 1 and 7.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "USER")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					USER = malloc(strlen(value)*sizeof(char)); 
					sprintf(USER, "%s",(char *) value);
					xmlFree(value);
					
				}
			}
			else if (strcmp((char *)cur_node->name, "PASSWORD")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					PASSWORD = malloc(strlen(value)*sizeof(char)); 
					sprintf(PASSWORD, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "CA_CERT")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					CA_CERT = malloc(strlen(value)*sizeof(char)); 
					sprintf(CA_CERT, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "CLIENT_CERT")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					CLIENT_CERT = malloc(strlen(value)*sizeof(char)); 
					sprintf(CLIENT_CERT, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "CLIENT_KEY")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					CLIENT_KEY = malloc(strlen(value)*sizeof(char)); 
					sprintf(CLIENT_KEY, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "PRIVATE_KEY")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					PRIVATE_KEY = malloc(strlen(value)*sizeof(char)); 
					sprintf(PRIVATE_KEY, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "FRAGMENT_SIZE")==0){
				if (pac){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &FRAG_SIZE);
					xmlFree(value);
				}
			}
        }

        parse_xml_client(cur_node->children);
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

static void
parse_xml_server(xmlNode * a_node)
{
#ifdef ISSERVER
    xmlNode *cur_node = a_node;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp((char *)cur_node->name, "PAC")==0) {
				paa=0;
				pac=1;
			}
			else if (strcmp((char *)cur_node->name, "PAA")==0) {
				paa=1;
				pac=0;
			}
			else if (strcmp((char *)cur_node->name, "PORT")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &SRCPORT);
					xmlFree(value);
					if (SRCPORT != 716){
						fprintf(stderr, "ERROR: PAA Port must be set to 716.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "TIMEOUT")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &LIFETIME_SESSION_TIMEOUT_CONFIG);
					xmlFree(value);
					if (LIFETIME_SESSION_TIMEOUT_CONFIG <=0){
						fprintf(stderr, "ERROR: PAA Session Timeout must be set to a number higher than 0.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "PRF")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &PRF_HMAC_SHA1);
					xmlFree(value);
					if (PRF_HMAC_SHA1 <=0 || PRF_HMAC_SHA1 > 4){
						fprintf(stderr, "ERROR: PAA PRF algorithm must be set to a number between 1 and 4.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "INTEGRITY")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &AUTH_HMAC_SHA1_160);
					xmlFree(value);
					if (AUTH_HMAC_SHA1_160 <=0 || AUTH_HMAC_SHA1_160 > 7){
						fprintf(stderr, "ERROR: PAA Integrity algorithm must be set to a number between 1 and 7.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "TIMEOUT_CLIENT")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG);
					xmlFree(value);
					if (LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG <=0){
						fprintf(stderr, "ERROR: PAA TIMEOUT CLIENT must be set to a number higher than 0.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "WORKERS")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &NUM_WORKERS);
					xmlFree(value);
					if (NUM_WORKERS <=0){
						fprintf(stderr, "ERROR: The worker's number must be set to a number higher than 0.\n");
						exit(1);
					}
				}
			}
			
			else if (strcmp((char *)cur_node->name, "TIME_ANSWER")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					sscanf(value, "%d", &TIME_PCI);
					xmlFree(value);
					if (TIME_PCI <=0){
						fprintf(stderr, "ERROR: The answer's time must be set to a number higher than 0.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "CA_CERT")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					CA_CERT = malloc(strlen(value)*sizeof(char)); 
					sprintf(CA_CERT, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "SERVER_CERT")==0){
				if (paa){
					char * value = (char *)xmlNodeGetContent(cur_node);
					SERVER_CERT = malloc(strlen(value)*sizeof(char)); 
					sprintf(SERVER_CERT, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "SERVER_KEY")==0){
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					SERVER_KEY = malloc(strlen(value)*sizeof(char)); 
					sprintf(SERVER_KEY, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "AS_IP")==0){
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					AS_IP = malloc(strlen(value)*sizeof(char)); 
					sprintf(AS_IP, "%s",(char *) value);
					xmlFree(value);
				}
			}
			else if (strcmp((char *)cur_node->name, "AS_PORT")==0){
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					sscanf(value, "%hd", &AS_PORT);
					xmlFree(value);
					if (AS_PORT <= 0){
						fprintf(stderr, "ERROR, The Authentication Server's Port must be higher than 0.\n");
						exit(1);
					}
				}
			}
			else if (strcmp((char *)cur_node->name, "SHARED_SECRET")==0){
				if (paa){
					char * value = (char*)xmlNodeGetContent(cur_node);
					AS_SECRET = malloc(strlen(value)*sizeof(char));
					sprintf(AS_SECRET, "%s",(char *) value);
					xmlFree(value);
				}
			}
        }

        parse_xml_server(cur_node->children);
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
    // FIXME: First check if DATADIR"/config.xml" exists, if it doesn't, try in current directory
    // then open the correct file
    doc = xmlReadFile(DATADIR"/config.xml", NULL, 0);

    if (doc == NULL) {
		fprintf(stderr,"Trying to load config.xml from current directory.\n");
		doc = xmlReadFile("config.xml", NULL, 0);
		if(doc==NULL){
			fprintf(stderr,"ERROR: could not parse file config.xml. \nThe application can't run without this file.\n" );
			exit(1);
		}
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
    // FIXME: First check if DATADIR"/config.xml" exists, if it doesn't, try in current directory
    // then open the correct file
    doc = xmlReadFile(DATADIR"/config.xml", NULL, 0);

    if (doc == NULL) {
		fprintf(stderr,"Trying to load config.xml from current directory.\n");
		doc = xmlReadFile("config.xml", NULL, 0);
		if(doc==NULL){
			fprintf(stderr,"ERROR: could not parse file config.xml. \nThe application can't run without this file.\n" );
			exit(1);
		}
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

#else
int main(void) {
    fprintf(stderr, "Tree support not compiled in\n");
    exit(1);
}
#endif
