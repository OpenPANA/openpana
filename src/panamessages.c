/*
 *  panamessages.c
 *
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 07/09/10.
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h> //Function htons()
#include <time.h> //To get random values

#include "panamessages.h"
#include "state_machines/statemachine.h"
#include "state_machines/session.h"
#include "panautils.h"
#include "prf_plus.h"

void generateAvp(avpList *lista, char *avp_name, void **data) {

    //For further information see RFC 5191 section 8
    int padding = 0; //Extra memory to complete the avp packet depending on the type

#ifdef DEBUG
    fprintf(stderr,"DEBUG: generateAvp Function\nDEBUG: Readed AVP: %s\n", avp_name);
#endif
    avp * elmnt = calloc(sizeof (avp), 1);
    if (NULL == elmnt) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }
    //All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
    elmnt->avp_flags = 0;
    elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver

    elmnt->value = NULL; //By now avp value is none
    elmnt->avp_length = 0; //So it's length is set to 0

    if (strcmp(avp_name, "AUTH") == 0) {
        //The AUTH AVP (AVP Code 1) is used to integrity protect PANA messages.
        //The AVP data payload contains the Message Authentication Code encoded
        //in network byte order. The AVP length varies depending on the
        //integrity algorithm used. The AVP data is of type OctetString.
        elmnt->avp_code = htons(AUTH_AVP); //FIXME: Magic Number
        elmnt->avp_length = htons(20); ////To get the 160bits result key
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}

        padding = paddingOctetString(ntohs(elmnt->avp_length));

    } else if (strcmp(avp_name, "EAP-Payload") == 0) {
        //The EAP-Payload AVP (AVP Code 2) is used for encapsulating the actual
        //EAP message that is being exchanged between the EAP peer and the EAP
        //authenticator. The AVP data is of type OctetString.
        elmnt->avp_code = htons(EAPPAYLOAD_AVP);
        
#ifdef DEBUG
        if (data[EAPPAYLOAD_AVP] == NULL) {
            fprintf(stderr,"DEBUG: Generating an EAP-Payload AVP without Payload.\n");
        }
#endif
		//Now eap packet is gonna be built
        struct wpabuf * aux = (struct wpabuf *) data[EAPPAYLOAD_AVP];
        const u8 * packet = wpabuf_head(aux);

#ifdef DEBUG
        fprintf(stderr,"BEGIN EAP PACKET\n");
        unsigned int i;
        for (i = 0; i < wpabuf_len(aux); i++) {
            fprintf(stderr,"%02x", packet[i]);
        }
        fprintf(stderr,"END EAP PACKET\n");
#endif

        elmnt->avp_length = htons(wpabuf_len(aux));
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        memcpy(elmnt->value, packet, ntohs(elmnt->avp_length));
        padding = paddingOctetString(ntohs(elmnt->avp_length));

    } else if (strcmp(avp_name, "Integrity-Algorithm") == 0) {
        //The Integrity-Algorithm AVP (AVP Code 3) is used for conveying the
        //integrity algorithm to compute an AUTH AVP. The AVP data is of type
        //Unsigned32. The AVP data contains an Internet Key Exchange Protocol
        //version 2 (IKEv2) Transform ID of Transform Type 3 [RFC4306] for the
        //integrity algorithm. All PANA implementations MUST support
        //AUTH_HMAC_SHA1_160 (7) [RFC4595].
        elmnt->avp_code = htons(INTEGRITYALG_AVP);
        
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
        elmnt->avp_length = htons(4); //FIXME Magic Number
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        //FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
        int option = ntohl((int) data[ntohs(elmnt->avp_code)]);
        memcpy(elmnt->value, &option, sizeof (int));

    } else if (strcmp(avp_name, "Key-Id") == 0) {
        //The Key-Id AVP (AVP Code 4) is of type Integer32 and contains an MSK
        //identifier. The MSK identifier is assigned by PAA and MUST be unique
        //within the PANA session.
        // AVP Integer32: (RFC 3588 4.2 )
		//32 bit signed value, in network byte order. 
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
        elmnt->avp_code = htons(KEYID_AVP);
        elmnt->avp_length = htons(4); //FIXME Magic Number
        elmnt->value = calloc(4, sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}

         memcpy(elmnt->value, data[ntohs(elmnt->avp_code)], 4);
    } else if (strcmp(avp_name, "Nonce") == 0) {
        //See section 8.5 RFC 5191
        elmnt->avp_code = htons(NONCE_AVP);

        //A random value is generated
        //It's supposed that the PaC and the PAA each are not
        //trusted with regard to the computation of a random nonce
        //A 20 octets random value will be generated
        elmnt->avp_length = htons(20); //FIXME Magic Number

        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
		if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        int i = 0;
        struct timeval seed;
        gettimeofday(&seed, NULL);
        srand(seed.tv_usec); /*initialize random generator using usecs*/

        for (i = 0; i <= ntohs(elmnt->avp_length); i += sizeof (int)) {
            int random = rand();
            //If we need the whole int value
            if ((i + sizeof (int)) <= ntohs(elmnt->avp_length)) {
                memcpy((elmnt->value + i), &random, sizeof (random));
            } else { //If only a part is needed
                memcpy((elmnt->value + i), &random, (ntohs(elmnt->avp_length) % sizeof (random)));
            }
        }
        padding = paddingOctetString(ntohs(elmnt->avp_length));

    } else if (strcmp(avp_name, "PRF-Algorithm") == 0) {
        //The PRF-Algorithm AVP (AVP Code 6) is used for conveying the
        //pseudo-random function to derive PANA_AUTH_KEY. The AVP data is of
        //type Unsigned32. The AVP data contains an IKEv2 Transform ID of
        //Transform Type 2 [RFC4306]. All PANA implementations MUST support
        //PRF_HMAC_SHA1 (2) [RFC2104].
        elmnt->avp_code = htons(PRFALG_AVP);
        //According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
        elmnt->avp_length = htons(4); //FIXME Magic Number
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        int option = ntohl((int) data[ntohs(elmnt->avp_code)]);
        memcpy(elmnt->value, &option, sizeof (int));

    } else if (strcmp(avp_name, "Result-Code") == 0) {
        //The Result-Code AVP (AVP Code 7) is of type Unsigned32 and indicates
        //whether an EAP authentication was completed successfully.
        elmnt->avp_code = htons(RESULTCODE_AVP);
        //According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
        elmnt->avp_length = htons(4); //FIXME Magic Number
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        int option = ntohs((int) data[ntohs(elmnt->avp_code)]);
        memcpy(elmnt->value, &option, sizeof (int));
        //The AVP Length field MUST be set to 12 (16 if the ’V’ bit is enabled).

    } else if (strcmp(avp_name, "Session-Lifetime") == 0) {
        //The Session-Lifetime AVP (AVP Code 8) contains the number of seconds
        //remaining before the current session is considered expired. The AVP
        //data is of type Unsigned32.
        elmnt->avp_code = htons(SESSIONLIFETIME_AVP);
        //According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
        elmnt->avp_length = htons(4); //FIXME Magic Number
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        if(elmnt->value == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        int option = htonl((int) data[ntohs(elmnt->avp_code)]);
        memcpy(elmnt->value, &option, sizeof (int));

    } else if (strcmp(avp_name, "Termination-Cause") == 0) {
        //See section 8.9 RFC 5191
        //SEE page 45 rfc 3588 AVP Type: Enumerated
        elmnt->avp_code = htons(TERMINATIONCAUSE_AVP);
        //According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
        elmnt->avp_length = htons(4); //FIXME Magic Number
        elmnt->value = calloc(ntohs(elmnt->avp_length), sizeof (char));
        int * valor;
        valor = (int *) elmnt->value;
        *valor = ntohs((int) data[ntohs(elmnt->avp_code)]);
        memcpy(elmnt->value, valor, sizeof (int));
    }
#ifdef DEBUG
    else {
        fprintf(stderr,"DEBUG: generateAvp function, invalid AVP name %s \n", avp_name);
    }
    //printf("\n\nDEBUG: Print AVP before adding it to the list.\n");
    //debug_print_avp(elmnt);
#endif
    
    //The AVP is added to the list
    //The size is the given by 4 shorts (panaHeader), the length of the
    //	avp value plus the padding if needed
	int sizeheader = (sizeof (unsigned short) *4);
    int sizeavp = sizeheader + ntohs(elmnt->avp_length) + padding;
    int oldsize = lista->size;

#ifdef DEBUG
    //fprintf(stderr,"DEBUG: SizeAVP calculated to use in memcpy: %d bytes.\n", sizeavp);
    //fprintf(stderr,"DEBUG: OLDSIZE : %d bytes.\n", oldsize);
#endif

    lista->size = lista->size + sizeavp; //Update the size with the new AVP
    lista->value = realloc(lista->value, lista->size); //Reserve the memory needed
    //The new memory is set to 0 (important so the padding is always 0)
    memset((lista->value + oldsize), 0, sizeavp);

	//Copy the avp header to the new area of the avp list
    memcpy((lista->value + oldsize), elmnt, sizeheader);
    //Now the value field is copied after the header
    memcpy((lista->value + oldsize + sizeheader), elmnt->value, ntohs(elmnt->avp_length));

    if (ntohs(elmnt->avp_length) > 0) {//Memory will be freed if needed
        free(elmnt->value);
    }
    free(elmnt);
    //debug_print_avp((avp *) (lista->value + oldsize));
}

char * transmissionMessage(char * msgtype, short flags, int *sequence_number, int sess_id, char * avps, struct sockaddr_in destaddr, void **data, int sock) {
	//Get the avp lists names parameter to a local variable.
	char * lista = NULL;
	lista = malloc(strlen(avps) +1);
	if(NULL == lista){
		fprintf(stderr,"Out of memory.\n");
		exit(1);
	}
	strcpy(lista, avps);

    if ((flags & R_FLAG) == R_FLAG) { //The R_FLAG mustn't be specified in
        // the parameters, it'll be ignored
#ifdef DEBUG
        fprintf(stderr,"DEBUG: WARNING, trasmissionMessage received R_FLAG as a parameter, it'll be ignored!.\n");
#endif
        flags = (flags & !(R_FLAG));
    }

    if (lista != NULL && strcmp(lista, "") != 0) { //Empty AVP lists will be ignored
        //This section looks for the AVP "AUTH" in the parameters and ignore
        //it in case is present.
        char sep[2] = "*"; //When an AVP name ends with "*", zero, one,
        //or more AVPs are inserted; otherwise, one AVP is
        //inserted. See RFC5609 page 8
        if(asprintf(&lista, "%s*", lista) == -1){ //A separation token is inserted,
			//asprintf returns -1 when errors occurs
			fprintf(stderr,"Out of memory");
			exit(1);
		}
        //free(oldlist);
        //avoids Segmentation Fault in
        //function strtok ahead.
        char *ptr = strtok(lista, sep); //Get the first avp name as a token
        char *lista2 = ""; //Auxiliar list to be filled with the avp list except AUTH
        if (strcmp(ptr, "AUTH") == 0) {//If is found, it'll be ignored
#ifdef DEBUG
            fprintf(stderr,"DEBUG: WARNING function transmissionMessage received \"AUTH\" AVP as a parameter, it'll be IGNORED.\n");
#endif
        } else {
            if(asprintf(&lista2, "%s*%s", lista2, ptr)==-1){ //The rest will be added to the new list
				//asprintf returns -1 when errors occurs
				fprintf(stderr,"Out of memory");
				exit(1);
			}
        }

        while ((ptr = strtok(NULL, sep)) != NULL) {//Add the rest of AVPs if any
            if (strcmp(ptr, "AUTH") == 0) {//If is found, it'll be ignored
#ifdef DEBUG
			fprintf(stderr,"DEBUG: WARNING function transmissionMessage received \"AUTH\" AVP as a parameter, it'll be IGNORED.\n");
#endif
            } else {
                if(asprintf(&lista2, "%s*%s", lista2, ptr)==-1){ //The rest will be added to the new list
					//asprintf returns -1 when errors occurs
					fprintf(stderr,"Out of memory");
					exit(1);
				}
            }
        }
        free(lista); //The wrong list is //freed
        lista = lista2; //The correct list is stablished as the new parameter
    }
    // The "flags" parameter will be modified in order to end with all the
    // flags that will be needed to the specified type of message

    // For further information see RFC 5191 page 25 section 7

    //Header's values to be included in panaMessage once they're initialized
    short msg_type = -1;
    int session_id = sess_id;

    //Different types of messages are identified and initialized
    if (strcmp(msgtype, "PCI") == 0) {//PANA-Client-Initiation, see RFC 5191 7.1

        //The Sequence Number and Session Identifier fields in this
        //message MUST be set to zero (0)
        *(sequence_number) = 0;
        session_id = 0;
        msg_type = PCI_MSG;
#ifdef DEBUG
        fprintf(stderr,"DEBUG: Tx PCI \n");
#endif
    } else if (strcmp(msgtype, "PAR") == 0) {//PANA-Auth-Request see RFC 5191 7.2

        msg_type = PAR_MSG;
        flags = flags | R_FLAG;

        //The message MUST NOT have both the ’S’ (Start) and ’C’
        //(Complete) bits set.
#ifdef DEBUG
        if (((flags & S_FLAG) == S_FLAG) && ((flags & C_FLAG) == C_FLAG)) {
			fprintf(stderr,"DEBUG: INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, C and S flags enabled at the same time.", msgtype);
        }
        fprintf(stderr,"DEBUG: Tx PAR \n");
#endif

    } else if (strcmp(msgtype, "PAN") == 0) {//PANA-Auth-Answer see RFC 5191 7.3

        msg_type = PAN_MSG;

        //The message MUST NOT have both the ’S’ (Start) and ’C’
        //(Complete) bits set.
#ifdef DEBUG
        if (((flags & S_FLAG) == S_FLAG) && ((flags & C_FLAG) == C_FLAG)) {
			fprintf(stderr,"DEBUG: INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, C and S flags enabled at the same time.", msgtype);
        }
        fprintf(stderr,"DEBUG: Tx PAN \n");
#endif

    } else if (strcmp(msgtype, "PTR") == 0) {//PANA-Termination-Request see RFC 5191 7.4

        msg_type = PTR_MSG;
        flags = flags | R_FLAG;

        //"Termination-Cause" AVPs must be added to the avp names list
        if(asprintf(&lista, "%s*Termination-Cause", lista)==-1){
			//asprintf returns -1 when errors occurs
			fprintf(stderr,"Out of memory");
			exit(1);
		}
#ifdef DEBUG
        fprintf(stderr,"DEBUG: Tx PTR \n");
#endif

    } else if (strcmp(msgtype, "PTA") == 0) {//PANA-Termination-Answer
        msg_type = PTA_MSG;
#ifdef DEBUG
        fprintf(stderr,"DEBUG: Tx PTA \n");
#endif

    } else if (strcmp(msgtype, "PNR") == 0) {//PANA-Notification-Request
        msg_type = PNR_MSG;
        flags = flags | R_FLAG;

        //The message MUST have one of the ’A’ (re-Authentication) and
        //’P’	(Ping) bits exclusively set.
        // (A||P)&&!(A&&P) <- Show an error if it isn't true
#ifdef DEBUG
        if (!((((A_FLAG & flags) == A_FLAG) || ((P_FLAG & flags) == P_FLAG)) && !(((A_FLAG & flags) == A_FLAG) && ((P_FLAG & flags) == P_FLAG)))) {
			fprintf(stderr,"DEBUG: INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, A and P flags are not set exclusively.", msgtype);
        }
        fprintf(stderr,"DEBUG: Tx PNR \n");
#endif

    } else if (strcmp(msgtype, "PNA") == 0) {//PANA-Notification-Answer
        msg_type = PNA_MSG;

        //The message MUST have one of the ’A’ (re-Authentication) and
        //’P’	(Ping) bits exclusively set.
        // (A||P)&&!(A&&P) <- Show an error if it isn't true
#ifdef DEBUG
        if (!((((A_FLAG & flags) == A_FLAG) || ((P_FLAG & flags) == P_FLAG)) && !(((A_FLAG & flags) == A_FLAG) && ((P_FLAG & flags) == P_FLAG)))) {
			fprintf(stderr,"DEBUG: INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, A and P flags are not set exclusively.", msgtype);
        }
        fprintf(stderr,"DEBUG: Tx PNA \n");
#endif

    }
#ifdef DEBUG
    else {
        fprintf(stderr,"DEBUG: transmissionMessage ERROR: Invalid Message!");
    }
#endif

    //The memory needed to create the PANA Header is reserved,
    //the memory for the AVPs will be reserved later
    panaMessage * msg = calloc(1, sizeof (panaMessage)); //The message is set to 0 by default
    if (NULL == msg) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }

    //We add the values needed to the message
    msg->header.flags = htons((msg->header.flags | flags)); //Flags are added
    //Check if its a Request message and update the sequence number if needed
    if ((ntohs(msg->header.flags) & R_FLAG) == R_FLAG) { //Request msg
        *(sequence_number) += 1;
    }
    msg->header.msg_type = htons(msg_type);
    msg->header.session_id = htonl(session_id);
    msg->header.seq_number = htonl(*(sequence_number));
    msg->header.msg_length = htons(sizeof (panaHeader)); //At the moment there's only the panaHeader size

    if (keyAvailable()) { //Is more efficient to only call "insertAvp" in thepana_session.SENDING_PORT end
        if(asprintf(&lista, "%s*AUTH", lista)==-1){
			//asprintf returns -1 when errors occurs
			fprintf(stderr,"Out of memory");
			exit(1);
		}
    }

    insertAvp(msg, lista, data); //The AVPs are inserted on the message
    free(lista); //lista is no longer needed.
	
    //If the message contains an auth avp, it must be encrypted
    if (existAvp(msg, "AUTH")) {
        cryptAuth(msg, data[AUTH_AVP], 40); //FIXME: Magic Number Porque de momento la clave es de 320 bits
    }
    
#ifdef DEBUG
    fprintf(stderr, "DEBUG: Message to be sent.\n");
    debug_print_message(msg);
#endif

	//The first PAN or PAN message and message with the Nonce AVP must 
    //be saved, they'll be used later in AUTH key generation.
    char * serializedMessage = NULL;

	//if(((flags & S_FLAG) == S_FLAG) || (strstr("Nonce",lista) != NULL)){
    //fprintf(stderr,"Ha cogido uno con el bit S\n");
    serializedMessage = serializePana(msg);
    //}

    int numbytes;
    numbytes = sendPana(destaddr, serializedMessage, sock);
    if (0 >= numbytes) {
        fprintf(stderr, "ERROR: sendPana in transmissionMessage.\n");
        exit(1);
    }

    //FIXME: Habría que liberar memoria del mensaje! fallo de segm en cliente?
    if (NULL != msg->avp_list && !existAvp(msg, "AUTH")) { //Fixme: No debería tener que poner la segunda condición
        free(msg->avp_list);
    }
    free(msg);

	
    return serializedMessage;
}

void insertAvp(panaMessage* msg, char * names, void **data) {


    if (msg == NULL) {//If there is no message given
#ifdef DEBUG
		fprintf(stderr,"DEBUG: insertAVP hasn't got any message, it MUST be used with a valid panaMessage.");
#endif
        return;
    }

    if (names != NULL && (strcmp(names, "") != 0)) { //If you're not going to insert any avp, skip this part
        avpList * lista;
        lista = calloc(sizeof (avpList), 1);
        if (NULL == lista) {
            fprintf(stderr, "ERROR: Out of memory.\n");
            exit(1);
        }
        lista->size = 0; //Initialize the list
        lista->value = NULL;

        char sep[2] = "*"; //When an AVP name ends with "*", zero, one,
        //or more AVPs are inserted; otherwise, one AVP is
        //inserted. See RFC5609 page 8
        
        
		//A separation token is inserted,
        //avoids Segmentation Fault in
        //function strtok ahead.
        if(asprintf(&names, "%s*", names)==-1){
			//asprintf returns -1 when errors occurs
			fprintf(stderr,"Out of memory");
			exit(1);
		}
        char *ptr = strtok(names, sep); //Get the first avp name as a token

        generateAvp(lista, ptr, data); //First AVP is added to the list

        while ((ptr = strtok(NULL, sep)) != NULL) {//Add the rest of AVPs if any
            generateAvp(lista, ptr, data);
        }

        //The memory used is msg_length except the header length
        int used = (ntohs(msg->header.msg_length) - sizeof (panaHeader));
        //If there were previous AVPs in the message, they'll be reallocated
        //before copying the new list of AVPs in the message body.

        msg->avp_list = realloc(msg->avp_list, (used + lista->size));
        memcpy((msg->avp_list + used), lista->value, lista->size);
        
        //Message Length is updated to the new value
        //panaHeader + previous list of avps size + new list of avps size
        msg->header.msg_length = htons(sizeof (panaHeader) + used + lista->size);
#ifdef DEBUG
        //fprintf(stderr,"DEBUG: Size updated to %d\n", ntohs(msg->header.msg_length));
#endif

        free(lista->value); //The temporal list is freed after the copy
        free(lista);
    }
#ifdef DEBUG
    else {
        fprintf(stderr,"DEBUG: insertAVP function used without AVP.\n");
    }
#endif
}

int existAvp(panaMessage * msg, char *avp_name) {
    int type = 0; //The AVP code to compare with the one in the panaMessage
	
    if (avp_name == NULL || (strcmp(avp_name, "") == 0)) { //If there's no name
        return 0;
    } else if (msg == NULL) { //If there's no message
        return 0;
    } else if (msg->header.msg_length == sizeof (panaHeader)) { //If the message has no value (no AVPs)
        return 0;
    }

    //First the AVP code is identified from the AVP_name
    if (strcmp(avp_name, "AUTH") == 0) {
        type = AUTH_AVP;
    } else if (strcmp(avp_name, "EAP-Payload") == 0) {
        type = EAPPAYLOAD_AVP;
    } else if (strcmp(avp_name, "Integrity-Algorithm") == 0) {
        type = INTEGRITYALG_AVP;
    } else if (strcmp(avp_name, "Key-Id") == 0) {
        type = KEYID_AVP;
    } else if (strcmp(avp_name, "Nonce") == 0) {
        type = NONCE_AVP;
    } else if (strcmp(avp_name, "PRF-Algorithm") == 0) {
        type = PRFALG_AVP;
    } else if (strcmp(avp_name, "Result-Code") == 0) {
        type = RESULTCODE_AVP;
    } else if (strcmp(avp_name, "Session-Lifetime") == 0) {
        type = SESSIONLIFETIME_AVP;
    } else if (strcmp(avp_name, "Termination-Cause") == 0) {
        type = TERMINATIONCAUSE_AVP;
    } else {
#ifdef DEBUG
        fprintf(stderr,"\nDEBUG: existAvp function, invalid AVP name %s \n", avp_name);
#endif
        return 0;
    }
    //FIXME utilizar la funcion getAvp
    //All the avp_codes in the panaMessage are compared with the one given
    //If there's no name
    int size = ntohs(msg->header.msg_length) - sizeof (panaHeader);
    int offset = 0; //Offset to point to the next AVP
    while (size > 0) {//While there are AVPs left
        avp * elmnt = (avp *) (msg->avp_list + offset); //Pointer to the next AVP
		int padding=0;
		
        if (ntohs(elmnt->avp_code) == type) {//If is a match return true
            return 1;
        }
        if (isOctetString(ntohs(elmnt->avp_code))){
			padding = paddingOctetString(ntohs(elmnt->avp_length));
		}
        size = size - (4 * sizeof (short) +ntohs(elmnt->avp_length)) - padding;
        offset = offset + (4 * sizeof (short) +ntohs(elmnt->avp_length)) + padding;
    }
    return 0;
}
