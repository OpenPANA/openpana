/**
 * section: Tree
 * synopsis: Navigates a tree to print element names
 * purpose: Parse a file to a tree, use xmlDocGetRootElement() to
 *          get the root element, then walk the document and print
 *          all the element name in document order.
 * usage: tree1 filename_or_URL
 * test: tree1 test2.xml > tree1.tmp ; diff tree1.tmp tree1.res ; rm tree1.tmp
 * author: Dodji Seketeli
 * copy: see Copyright for the status of this software.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "loadconfig.h"

#ifdef LIBXML_TREE_ENABLED

/*
 *To compile this file using gcc you can type
 *gcc `xml2-config --cflags --libs` -o xmlexample libxml2-example.c
 */

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
			if (strcmp(cur_node->name, "PAC")==0) {
				paa=0;
				pac=1;
			}
			else if (strcmp(cur_node->name, "PAA")==0) {
				paa=1;
				pac=0;
			}
			else if (strcmp(cur_node->name, "IP")==0){
				if (paa){

					DESTIP = malloc(16*sizeof(char));
					sprintf(DESTIP, "%s", xmlNodeGetContent(cur_node));
				}
				else if (pac) {
					LOCALIP = malloc(16*sizeof(char));
					sprintf(LOCALIP, "%s", xmlNodeGetContent(cur_node));
				}
			}
			else if (strcmp(cur_node->name, "PORT")==0){
				if (paa){

					sscanf(xmlNodeGetContent(cur_node), "%d", &DSTPORT);
				}
				else if (pac) {
					sscanf(xmlNodeGetContent(cur_node), "%d", &SRCPORT);
				}
			}
			else if (strcmp(cur_node->name, "TIMEOUT")==0){
				if (pac) {
					sscanf(xmlNodeGetContent(cur_node), "%d", &FAILED_SESS_TIMEOUT_CONFIG);
				}
			}
			else if (strcmp(cur_node->name, "PRF")==0){
				if (pac) {
					sscanf(xmlNodeGetContent(cur_node), "%d", &PRF_HMAC_SHA1);
				}
			}
			else if (strcmp(cur_node->name, "INTEGRITY")==0){
				if (pac) {
					sscanf(xmlNodeGetContent(cur_node), "%d", &AUTH_HMAC_SHA1_160);
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
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp(cur_node->name, "PAC")==0) {
				paa=0;
				pac=1;
			}
			else if (strcmp(cur_node->name, "PAA")==0) {
				paa=1;
				pac=0;
			}
			else if (strcmp(cur_node->name, "PORT")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &SRCPORT);
				}
			}
			else if (strcmp(cur_node->name, "TIMEOUT")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &LIFETIME_SESSION_TIMEOUT_CONFIG);
				}
			}
			else if (strcmp(cur_node->name, "PRF")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &PRF_HMAC_SHA1);
				}
			}
			else if (strcmp(cur_node->name, "INTEGRITY")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &AUTH_HMAC_SHA1_160);
				}
			}
			else if (strcmp(cur_node->name, "TIMEOUT_CLIENT")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG);
				}
			}
			else if (strcmp(cur_node->name, "WORKERS")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &NUM_WORKERS);
				}
			}
			
			else if (strcmp(cur_node->name, "TIME_ANSWER")==0){
				if (paa){
					sscanf(xmlNodeGetContent(cur_node), "%d", &TIME_PCI);
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
    doc = xmlReadFile("config.xml", NULL, 0);

    if (doc == NULL) {
        printf("error: could not parse file config.xml\n" );
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
    doc = xmlReadFile("config.xml", NULL, 0);

    if (doc == NULL) {
        printf("error: could not parse file config.xml\n" );
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
