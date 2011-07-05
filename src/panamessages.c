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

int AVPname2flag(char * avp_name){
	int type=0;
	//fprintf(stderr,"DEBUG: AVP: %s, type %x \n",avp_name,type);
	//The AVP flag is setted from the AVP_name
    if (strcmp(avp_name, "AUTH") == 0) {
        type = F_AUTH;
    } else if (strcmp(avp_name, "EAP-Payload") == 0) {
        type = F_EAPP;
    } else if (strcmp(avp_name, "Integrity-Algorithm") == 0) {
        type = F_INTEG;
    } else if (strcmp(avp_name, "Key-Id") == 0) {
        type = F_KEYID;
    } else if (strcmp(avp_name, "Nonce") == 0) {
        type = F_NONCE;
    } else if (strcmp(avp_name, "PRF-Algorithm") == 0) {
        type = F_PRF;
    } else if (strcmp(avp_name, "Result-Code") == 0) {
        type = F_RES;
    } else if (strcmp(avp_name, "Session-Lifetime") == 0) {
        type = F_SESS;
    } else if (strcmp(avp_name, "Termination-Cause") == 0) {
        type = F_TERM;
    } else {
#ifdef DEBUG
        fprintf(stderr,"\nDEBUG: AVPname2floag function, invalid AVP name %s \n", avp_name);
#endif
        type = 0;
    }
    //fprintf(stderr,"FLAG: 0x%x\n",type);
    return type;
}

int AVPgenerateflags(char * avps){
	
	if(avps == NULL)
		return 0;
	
	int result = 0;
	//Get the avp lists names parameter to a local variable.
	char * names = NULL;
	//an extra space is required to insert an extra separation token later
	names = calloc(strlen(avps) +2,sizeof(char));
	
	if(NULL == names){
		fprintf(stderr,"Out of memory.\n");
		exit(1);
	}
	strcpy(names, avps);
	if (strcmp(names, "") != 0) { //If you're not going to insert any avp, skip this part

        char sep[2] = "*"; //When an AVP name ends with "*", zero, one,
        //or more AVPs are inserted; otherwise, one AVP is
        //inserted. See RFC5609 page 8
        
		//A separation token is inserted in the end,
        //avoids Segmentation Fault in
        //function strtok ahead.
		names[strlen(avps)] = '*';        
        char *ptr = NULL;
        ptr = strtok(names, sep); //Get the first avp name as a token
		
		//Added to the privisional result
		result = result | AVPname2flag(ptr);

        while ((ptr = strtok(NULL, sep)) != NULL) {//Add the rest of AVPs if any
			result = result | AVPname2flag(ptr);
        }
    }
#ifdef DEBUG
    else {
        fprintf(stderr,"DEBUG: AVPname2flag function used without AVP.\n");
    }
#endif
	
	//Ignore AUTH AVP if present
	if(result & F_AUTH){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: WARNING function AVPgenerateflags received \"AUTH\" AVP as a parameter, it'll be IGNORED.\n");
		#endif
		//FIXME: Debería hacerse lógicamente, pero no va
		result = (result - F_AUTH);
	}
	free(names);	
	return result;
}


char * transmissionMessage(char * msgtype, short flags, int *sequence_number, int sess_id, char * avps, struct sockaddr_in destaddr, void **data, int sock) {
//First, the msgtype argument is checked, it must meet certain conditions
	//- Message type must have 3 positions
	//- All messages start with 'P'
	//- The second letter must be:
	// 	'A' -> 3º must be 'R' or 'N'
	// 	'C' -> 3º must be 'I'
	// 	'N' or 'T' -> 3º must be 'A' or 'R'
	// 	1P && ( (2A && (3R || 3N)) || (2C && 3I) || ((2N || 2T) && (3A || R)) )
	//			is valid, so !() must be ignored
	// If any of those is unmeet, tx will return an error.
	if(strlen(msgtype) != 3 || !( msgtype[0] == 'P' && ( (msgtype[1] == 'A' && (msgtype[2] == 'R' ||
		msgtype[2] == 'N')) || (msgtype[1] == 'C' && msgtype[2] == 'I') || 
		((msgtype[1] == 'N' || msgtype[1] == 'T') && (msgtype[2] == 'A' || 
											  msgtype[2] == 'R')) )    )){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: transmissionMessage ERROR: Invalid Message: %s\n",msgtype);
		#endif
		return NULL;
	}
	
	if(sequence_number == NULL){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: transmissionMessage ERROR: sequence number its NULL.\n");
		#endif
		return NULL;
	}
	
	//fprintf(stderr,"AVPs a insertar: %s\n",avps);
	
    if (flags & R_FLAG) { //The R_FLAG mustn't be specified in
        // the parameters, it'll be ignored
#ifdef DEBUG
        fprintf(stderr,"DEBUG: WARNING, trasmissionMessage received R_FLAG as a parameter, it'll be ignored!.\n");
#endif
        flags = (flags & !(R_FLAG));
    }

    // The "flags" parameter will be modified in order to end with all the
    // flags that will be needed to the specified type of message
    // For further information see RFC 5191 page 25 section 7

	//See what AVPs will be needed:
	int avpsflags = AVPgenerateflags(avps);


    //Header's values to be included in panaMessage once they're initialized
    short msg_type = -1;
    int session_id = sess_id;

    //Different types of messages are identified and initialized
    if(msgtype[1] == 'C'){//msgtype == "PCI" PANA-Client-Initiation, see RFC 5191 7.1
		//The Sequence Number and Session Identifier fields in this
        //message MUST be set to zero (0)
		*(sequence_number) = 0;
        session_id = 0;
        msg_type = PCI_MSG;
        #ifdef DEBUG
        fprintf(stderr,"DEBUG: Tx PCI \n");
		#endif
	} else if ( msgtype[1] == 'A' ){ //PANA Auth Message see RFC 5191 7.2 & 7.3

        msg_type = PAR_MSG; // or it could be PAN_MSG, same value

        //The message MUST NOT have both the ’S’ (Start) and ’C’
        //(Complete) bits set.
        if ((flags & S_FLAG) && (flags & C_FLAG)) {
			#ifdef DEBUG
			fprintf(stderr,"DEBUG: INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, C and S flags enabled at the same time.\n", msgtype);
			#endif
			return NULL;
        }
        
        if( msgtype[2] == 'R'){//See if its a request or not
			flags = flags | R_FLAG;
			#ifdef DEBUG
			fprintf(stderr,"DEBUG: Tx PAR \n");
			#endif
		}
		#ifdef DEBUG
        else {
			fprintf(stderr,"DEBUG: Tx PAN \n");
		}
		#endif
    } else if (msgtype[1] == 'T'){//PANA-Termination message see RFC 5191 7.4

        msg_type = PTR_MSG;// or it could be PTA_MSG, same value
        
        if( msgtype[2] == 'R'){//See if its a request or not
			flags = flags | R_FLAG; 
			
			//"Termination-Cause" AVP must be added to the avp list
			avpsflags = avpsflags | F_TERM ;
			#ifdef DEBUG
			fprintf(stderr,"DEBUG: Tx PTR \n");
			#endif
		}
		#ifdef DEBUG
        else {
			fprintf(stderr,"DEBUG: Tx PTA \n");
		}
		#endif
	} else if(msgtype[1] == 'N'){//PANA-Notification message
        msg_type = PNR_MSG;//Or it could be PNA_MSG, same value
        
        //The message MUST have one of the ’A’ (re-Authentication) and
        //’P’	(Ping) bits exclusively set.
        // (A||P)&&!(A&&P) <- Show an error if it isn't true
        if (!(((A_FLAG & flags) || (P_FLAG & flags)) && !((A_FLAG & flags) && (P_FLAG & flags)))) {
			#ifdef DEBUG
			fprintf(stderr,"DEBUG: INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, A and P flags are not set exclusively.\n", msgtype);
			#endif
			return NULL;
        }
        
		if( msgtype[2] == 'R'){//See if its a request or not
			flags = flags | R_FLAG;
			#ifdef DEBUG
			fprintf(stderr,"DEBUG: Tx PNR \n");
			#endif
		}
		#ifdef DEBUG
        else {
			fprintf(stderr,"DEBUG: Tx PNA \n");
		}
		#endif      
    }

    //The memory needed to create the PANA Header is reserved,
    //the memory for the AVPs will be reserved later
    char ** message;
    char *pana_message = calloc(1, sizeof (pana)); //The message is set to 0 by default    
    message = & pana_message;
    pana * msg = (pana*) pana_message;
    if (NULL == msg) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }
    
    //We add the values needed to the message
    msg->flags = htons(flags); //Flags are added
    
    //Check if its a Request message and update the sequence number if needed
    if ( flags & R_FLAG ){ //Request msg
        *(sequence_number) += 1;
    }
    
    msg->msg_type = htons(msg_type);
    msg->session_id = htonl(session_id);
    msg->seq_number = htonl(*sequence_number);
    msg->msg_length = htons(sizeof (pana)); //At the moment there's only the PANA header size
	
    if (keyAvailable()) { 
		avpsflags = avpsflags | F_AUTH ;
    }
    
    insertAvps(message, avpsflags, data); //The AVPs are inserted on the message
	msg =(pana*) *message; //Update from insertAvps parameter 

#ifdef DEBUG
    fprintf(stderr, "DEBUG: Message to be sent.\n");
    debug_pana(msg);
#endif
	
    int numbytes;
    numbytes = sendPana(destaddr, (char*)msg, sock);
    if (0 >= numbytes) {
        fprintf(stderr, "ERROR: sendPana in transmissionMessage.\n");
        exit(1);
    }
	return (char*)msg;
}
	
int existAvp(char * message, char *avp_name) {
    int type = 0; //The AVP code to compare with the one in the panaMessage
	pana * msg = (pana *) message;
    if (avp_name == NULL || (strcmp(avp_name, "") == 0)) { //If there's no name
        return 0;
    } else if (msg == NULL) { //If there's no message
        return 0;
    } else if (msg->msg_length == sizeof (pana)) { //If the message has no value (no AVPs)
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
        return FALSE;
    }
    /*#ifdef DEBUG
    fprintf(stderr,"\nDEBUG: existAvp function, AVP name %s, AVP CODE:%d \n***\n***\nMENSAJE PANA COMPLETO:\n", avp_name,type);
    debug_pana(msg);
    #endif*/
    if(getAvp(message,type)==NULL){
		return FALSE;
	}
	else{
		return TRUE;
	}
}
int insertAvps(char** message, int avps, void **data) {
	char * msg = *message;
	if (avps == 0){ //If you're not going to insert any avp
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: insertAVPs function used without AVP.\n");
		#endif
		return 0;
	}

    if (msg == NULL) {//If there is no message given
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: insertAVPs hasn't got any message, it MUST be used with a valid pana message.");
		#endif
        return 0;
    }
    //fprintf(stderr,"AVPS: %x\n",avps);
    int totalsize = sizeof(pana);
    //fprintf(stderr,"Totalsize: %d\n",totalsize);

    int stride = totalsize;
    char * position = msg;
    avp_pana * elmnt = NULL;
    int avpsize=0;
    
    //FIXME en los que necesitan data asegurarnos que hay algo
    //para poner y si no hay mostrar error y no generar el AVP
    if(F_INTEG & avps){
		//The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + 4; //FIXME Magic Number
		totalsize += avpsize;
		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
		elmnt->length =htons(avpsize - sizeof(avp_pana)); 
		
		 //The Integrity-Algorithm AVP (AVP Code 3) is used for conveying the
        //integrity algorithm to compute an AUTH AVP. The AVP data is of type
        //Unsigned32. The AVP data contains an Internet Key Exchange Protocol
        //version 2 (IKEv2) Transform ID of Transform Type 3 [RFC4306] for the
        //integrity algorithm. All PANA implementations MUST support
        //AUTH_HMAC_SHA1_160 (7) [RFC4595].
        elmnt->code = htons(INTEGRITYALG_AVP);

        //FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
        int option = ntohl((int) data[INTEGRITYALG_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (int));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
	}
    if(F_KEYID & avps){
		//The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + 4; //FIXME Magic Number
		totalsize += avpsize;
		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
		elmnt->length =htons(avpsize - sizeof(avp_pana));
		
		//The Key-Id AVP (AVP Code 4) is of type Integer32 and contains an MSK
        //identifier. The MSK identifier is assigned by PAA and MUST be unique
        //within the PANA session.
        // AVP Integer32: (RFC 3588 4.2 )
        //				32 bit signed value, in network byte order. 
        elmnt->code = htons(KEYID_AVP);
		//FIXME comprobar el data que haya algo
		memcpy(position + sizeof(avp_pana), data[KEYID_AVP], avpsize - sizeof(avp_pana));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
	}
    if(F_NONCE & avps){
		//A random value is generated
        //It's supposed that the PaC and the PAA each are not
        //trusted with regard to the computation of a random nonce
        //A 20 octets random value will be generated
		avpsize = sizeof(avp_pana) + 20; //FIXME Magic Number? not magic!
		int padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		totalsize += avpsize + padding;

		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
	
		elmnt->length =htons(avpsize - sizeof(avp_pana));
		
		//See section 8.5 RFC 5191
        elmnt->code = htons(NONCE_AVP);
		
        struct timeval seed;
        gettimeofday(&seed, NULL);
        srand(seed.tv_usec); //initialize random generator using usecs

        for (unsigned int i = 0; i <= (avpsize - sizeof(avp_pana)); i += sizeof (int)) {
            int random = rand();
            //If we need the whole int value
            if ((i + sizeof (int)) <= (avpsize - sizeof(avp_pana))) {
                memcpy((position + sizeof(avp_pana) + i), &random, sizeof (random));
            } else { //If only a part is needed
                memcpy((position + sizeof(avp_pana) + i), &random, (avpsize - sizeof(avp_pana)) % sizeof (random));
            }
        }
        
		memset(position + avpsize,0,padding);
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize+padding;
	}
    if(F_PRF & avps){
		//The PRF-Algorithm AVP (AVP Code 6) is used for conveying the
        //pseudo-random function to derive PANA_AUTH_KEY. The AVP data is of
        //type Unsigned32. The AVP data contains an IKEv2 Transform ID of
        //Transform Type 2 [RFC4306]. All PANA implementations MUST support
        //PRF_HMAC_SHA1 (2) [RFC2104].
        //The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + 4; //FIXME Magic Number
		totalsize += avpsize;
		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
		elmnt->length =htons(avpsize - sizeof(avp_pana));
        elmnt->code = htons(PRFALG_AVP);

        int option = ntohl((int) data[PRFALG_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (int));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
        
	}
    if(F_RES & avps){
		//The Result-Code AVP (AVP Code 7) is of type Unsigned32 and indicates
        //whether an EAP authentication was completed successfully.
        //The PRF-Algorithm AVP (AVP Code 6) is used for conveying the
        //pseudo-random function to derive PANA_AUTH_KEY. The AVP data is of
        //type Unsigned32. The AVP data contains an IKEv2 Transform ID of
        //Transform Type 2 [RFC4306]. All PANA implementations MUST support
        //PRF_HMAC_SHA1 (2) [RFC2104].
        //The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + 4; //FIXME Magic Number
		totalsize += avpsize;
		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
		elmnt->length =htons(avpsize - sizeof(avp_pana));
        elmnt->code = htons(RESULTCODE_AVP);

        int option = ntohl((int) data[RESULTCODE_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (int));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
	}
    if(F_SESS & avps){
		//The Session-Lifetime AVP (AVP Code 8) contains the number of seconds
        //remaining before the current session is considered expired. The AVP
        //data is of type Unsigned32.
        //The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + 4; //FIXME Magic Number
		totalsize += avpsize;
		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
		elmnt->length =htons(avpsize - sizeof(avp_pana)); 
        elmnt->code = htons(SESSIONLIFETIME_AVP);

        //FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
        int option = ntohl((int) data[SESSIONLIFETIME_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (int));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
	}
    if(F_TERM & avps){
		//See section 8.9 RFC 5191
        //SEE page 45 rfc 3588 AVP Type: Enumerated
        //The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + 4; //FIXME Magic Number
		totalsize += avpsize;
		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled). But with PANA, the AVP Length
		//field DOES NOT include the header size, so size will be 
		// 12 - panaHeader = 4.
		elmnt->length =htons(avpsize - sizeof(avp_pana)); 
        elmnt->code = htons(TERMINATIONCAUSE_AVP);

        //FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
        int * valor;
        valor = (int *)(position + sizeof(avp_pana));
        *valor = ntohs((int) data[TERMINATIONCAUSE_AVP]);
        memcpy(position + sizeof(avp_pana), valor, sizeof (int));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
	}
    if(F_EAPP & avps){ //FIXME Falta por comprobar que funciona
		//The EAP-Payload AVP (AVP Code 2) is used for encapsulating the actual
        //EAP message that is being exchanged between the EAP peer and the EAP
        //authenticator. The AVP data is of type OctetString.
        //A random value is generated
        //It's supposed that the PaC and the PAA each are not
        //trusted with regard to the computation of a random nonce
        //A 20 octets random value will be generated
        
        #ifdef DEBUG
        if (data[EAPPAYLOAD_AVP] == NULL) {
            fprintf(stderr,"DEBUG: Generating an EAP-Payload AVP without Payload.\n");
        }
		#endif
        
        //Now eap packet is gonna be built
        struct wpabuf * aux = (struct wpabuf *) data[EAPPAYLOAD_AVP];
        const u8 * packet = wpabuf_head(aux);

		/*#ifdef DEBUG
        fprintf(stderr,"BEGIN EAP PACKET\n");
        unsigned int i;
        for (i = 0; i < wpabuf_len(aux); i++) {
            fprintf(stderr,"%02x", packet[i]);
        }
        fprintf(stderr,"END EAP PACKET\n");
		#endif*/
        
		avpsize = sizeof(avp_pana) + wpabuf_len(aux); //FIXME Magic Number? not magic!
		int padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		totalsize += avpsize + padding;

		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
	
		elmnt->length =htons(avpsize - sizeof(avp_pana));
		//See section 8.5 RFC 5191
        elmnt->code = htons(EAPPAYLOAD_AVP);
		

		memcpy(position + sizeof(avp_pana), packet, wpabuf_len(aux));                
		memset(position + avpsize,0,padding);
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize+padding;
	}
    //This is the last one to be added because
    //If the message contains an auth avp, it must be encrypted
    if(F_AUTH & avps){  
		//The AUTH AVP (AVP Code 1) is used to integrity protect PANA messages.
        //The AVP data payload contains the Message Authentication Code encoded
        //in network byte order. The AVP length varies depending on the
        //integrity algorithm used. The AVP data is of type OctetString.
        //AVP value size = 20, to get the 160bits result key
        avpsize = sizeof(avp_pana) + 20; //FIXME Magic Number
		int padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		totalsize += avpsize + padding;

		msg = realloc(msg,totalsize);
		if(msg == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
	
		elmnt->length =htons(avpsize - sizeof(avp_pana));
		
		//See section 8.5 RFC 5191
        elmnt->code = htons(AUTH_AVP);
		
		//Set the value and padding to 0
		memset(position + sizeof(avp_pana),0,avpsize - sizeof(avp_pana) + padding);
		
		//In order to get the complete message to hash, the size value
		//must be updated
		((pana *)msg)->msg_length = htons(totalsize);
		
		//If the message contains an auth avp, it must be hashed
        hashAuth(msg, data[AUTH_AVP], 40); //FIXME: Magic Number Porque de momento la clave es de 320 bits
        //stride += avpsize+padding;//No more avps, it's unnecesary to update this value
	}
    
	//fprintf(stderr,"Totalsize: %d\n",totalsize);
	//Finally totalsize is changed on PANA message
	((pana *)msg)->msg_length = htons(totalsize);
	//fprintf(stderr,"Totalsize: %d\n",ntohs(((pana *)msg)->msg_length));
	//debug_pana((pana*)msg);
	*message = msg;
	return totalsize;
}
