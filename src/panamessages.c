/**
 * @file panamessages.c
 * @brief  Functions to work with PANA messages.
 **/
/*
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

#include "panamessages.h"
#include "state_machines/statemachine.h"
#include "state_machines/session.h"
#include "panautils.h"
#include "prf_plus.h"

int AVPname2flag(char * avp_name){
	int type=0;
	
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
		pana_debug("WARNING AVPname2flag function, invalid AVP name %s", avp_name);
        type = 0;
    }
    
    return type;
}

int AVPgenerateflags(char * avps){
	
	if(avps == NULL)
		return 0;
	
	int result = 0;
	//Get the avp lists names parameter to a local variable.
	char * names = NULL;
	//an extra space is required to insert an extra separation token later
	names = XCALLOC(char,strlen(avps) +2);
	
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
    else {
		pana_debug("WARNING: AVPname2flag function used without AVP");
	}
	
	//Ignore AUTH AVP if present
	if(result & F_AUTH){
		pana_debug("WARNING function AVPgenerateflags received \"AUTH\" AVP as a parameter, it'll be IGNORED");
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
		pana_debug("transmissionMessage ERROR: Invalid Message: %s",msgtype);
		return NULL;
	}
	
	if(sequence_number == NULL){
		pana_debug("transmissionMessage ERROR: sequence number its NULL");
		return NULL;
	}
	
	//fprintf(stderr,"AVPs a insertar: %s\n",avps);
	
    if (flags & R_FLAG) { //The R_FLAG mustn't be specified in
        // the parameters, it'll be ignored
        pana_debug("WARNING, trasmissionMessage received R_FLAG as a parameter, it'll be ignored!");
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
        pana_debug("Tx PCI");
	} else if ( msgtype[1] == 'A' ){ //PANA Auth Message see RFC 5191 7.2 & 7.3

        msg_type = PAR_MSG; // or it could be PAN_MSG, same value

        //The message MUST NOT have both the ’S’ (Start) and ’C’
        //(Complete) bits set.
        if ((flags & S_FLAG) && (flags & C_FLAG)) {
			pana_debug("INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, C and S flags enabled at the same time", msgtype);
			return NULL;
        }
        
        if( msgtype[2] == 'R'){//See if its a request or not
			flags = flags | R_FLAG;
			pana_debug("Tx PAR");
		}
        else {
			pana_debug("Tx PAN");
		}
    } else if (msgtype[1] == 'T'){//PANA-Termination message see RFC 5191 7.4

        msg_type = PTR_MSG;// or it could be PTA_MSG, same value
        
        if( msgtype[2] == 'R'){//See if its a request or not
			flags = flags | R_FLAG; 
			
			//"Termination-Cause" AVP must be added to the avp list
			avpsflags = avpsflags | F_TERM ;
			pana_debug("Tx PTR");
		}
        else {
			pana_debug("Tx PTA");
		}
	} else if(msgtype[1] == 'N'){//PANA-Notification message
        msg_type = PNR_MSG;//Or it could be PNA_MSG, same value
        
        //The message MUST have one of the ’A’ (re-Authentication) and
        //’P’	(Ping) bits exclusively set.
        // (A||P)&&!(A&&P) <- Show an error if it isn't true
        if (!(((A_FLAG & flags) || (P_FLAG & flags)) && !((A_FLAG & flags) && (P_FLAG & flags)))) {
			pana_debug("INVALID MESSAGE, transmissionMessage, a wrong message %s has been built, A and P flags are not set exclusively", msgtype);
			return NULL;
        }
        
		if( msgtype[2] == 'R'){//See if its a request or not
			flags = flags | R_FLAG;
			pana_debug("Tx PNR");
		}
        else {
			pana_debug("Tx PNA");
		}
    }

    //The memory needed to create the PANA Header is reserved,
    //the memory for the AVPs will be reserved later
    char ** message;
    char *pana_message = XCALLOC(pana,1); //The message is set to 0 by default    
    message = & pana_message;
    pana * msg = (pana*) pana_message;
    
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

    pana_debug("Message to be sent");
    debug_msg(msg);
	
    int numbytes;
    numbytes = sendPana(destaddr, (char*)msg, sock);
    if (0 >= numbytes) {
        fprintf(stderr, "ERROR: sendPana in transmissionMessage.\n");
        exit(EXIT_FAILURE);
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
		pana_debug("existAvp function, invalid AVP name %s", avp_name);
        return FALSE;
    }
    /*#ifdef DEBUG
    fprintf(stderr,"\nDEBUG: existAvp function, AVP name %s, AVP CODE:%d \n***\n***\nMENSAJE PANA COMPLETO:\n", avp_name,type);
    debug_msg(msg);
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
		pana_debug("insertAVPs function used without AVP");
		return 0;
	}

    if (msg == NULL) {//If there is no message given
		pana_debug("insertAVPs hasn't got any message, it MUST be used with a valid pana message");
        return 0;
    }
    
    int totalsize = sizeof(pana);
    int stride = totalsize;
    char * position = msg;
    avp_pana * elmnt = NULL;
    int avpsize=0;
    
    //FIXME en los que necesitan data asegurarnos que hay algo
    //para poner y si no hay mostrar error y no generar el AVP
    if(F_INTEG & avps){
		//The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + INTEG_AVP_VALUE_LENGTH; 
		totalsize += avpsize;
		msg = XREALLOC(char,msg,totalsize);
		
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
		avpsize = sizeof(avp_pana) + KEY_ID_LENGTH; 
		totalsize += avpsize;
		msg = XREALLOC(char,msg,totalsize);
		
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
		avpsize = sizeof(avp_pana) + NONCE_AVP_VALUE_LENGTH; 
		int padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		totalsize += avpsize + padding;

		msg = XREALLOC(char,msg,totalsize);
		
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
	
		elmnt->length =htons(avpsize - sizeof(avp_pana));
		
		//See section 8.5 RFC 5191
        elmnt->code = htons(NONCE_AVP);
		
        srand(getTime()); //initialize random generator using time

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
		avpsize = sizeof(avp_pana) + PRF_AVP_VALUE_LENGTH; 
		totalsize += avpsize;
		msg = XREALLOC(char,msg,totalsize);
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

        uint32_t option = ntohl((uint32_t) data[PRFALG_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (uint32_t));
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
		avpsize = sizeof(avp_pana) + RESCODE_AVP_VALUE_LENGTH; 
		totalsize += avpsize;
		msg = XREALLOC(char,msg,totalsize);
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

        uint32_t option = ntohl((uint32_t) data[RESULTCODE_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (uint32_t));
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
		avpsize = sizeof(avp_pana) + SESSLIFETIME_AVP_VALUE_LENGTH; 
		totalsize += avpsize;
		msg = XREALLOC(char,msg,totalsize);
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
        uint32_t option = ntohl((uint32_t) data[SESSIONLIFETIME_AVP]);
        memcpy(position + sizeof(avp_pana), &option, sizeof (uint32_t));
        //debug_avp(elmnt);
        //Update message values
        stride += avpsize;
	}
    if(F_TERM & avps){
		//See section 8.9 RFC 5191
        //SEE page 45 rfc 3588 AVP Type: Enumerated
        //The total size of this AVP is: AVP header + its value field
		//it will be needed 12 bytes
		avpsize = sizeof(avp_pana) + TERMCAUSE_AVP_VALUE_LENGTH; 
		totalsize += avpsize;
		msg = XREALLOC(char,msg,totalsize);
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
        uint32_t * valor;
        valor = (uint32_t *)(position + sizeof(avp_pana));
        *valor = ntohs((uint32_t) data[TERMINATIONCAUSE_AVP]);
        memcpy(position + sizeof(avp_pana), valor, sizeof (uint32_t));
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
        
        if (data[EAPPAYLOAD_AVP] == NULL) {
			pana_debug("Generating an EAP-Payload AVP without Payload");
        }
        
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
        
		avpsize = sizeof(avp_pana) + wpabuf_len(aux);
		int padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		totalsize += avpsize + padding;

		msg = XREALLOC(char,msg,totalsize);
		
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
        avpsize = sizeof(avp_pana) + AUTH_AVP_VALUE_LENGTH; 
		int padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		totalsize += avpsize + padding;

		msg = XREALLOC(char,msg,totalsize);
		
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
        hashAuth(msg, data[AUTH_AVP], MSK_LENGTH); 
        //stride += avpsize+padding;//No more avps, it's unnecesary to update this value
	}
    
	//fprintf(stderr,"Totalsize: %d\n",totalsize);
	//Finally totalsize is changed on PANA message
	((pana *)msg)->msg_length = htons(totalsize);
	//fprintf(stderr,"Totalsize: %d\n",ntohs(((pana *)msg)->msg_length));
	//debug_msg((pana*)msg);
	*message = msg;
	return totalsize;
}

char * getAvp(char *msg, int type) {
    char * elmnt = NULL;

    int size = ntohs(((pana*)msg)->msg_length) - sizeof (pana);
    int offset = sizeof(pana); //Offset to point to the next AVP
    
    while (size > 0) {//While there are AVPs left
        elmnt = msg + offset; //Pointer to the next AVP
		int padding = 0;
		int code = ntohs(((avp_pana *)elmnt)->code);
		if ( code == type) {//If is a match return true
            return elmnt;
        }
        int length = ntohs(((avp_pana *)elmnt)->length);
        if (isOctetString(code)){
			padding = paddingOctetString(length);
		}
        size = size - sizeof(avp_pana) - length - padding;
        offset = offset + sizeof(avp_pana) + length + padding;
    }

    return NULL; //Not found
}

char * getAvpName(int avp_code) {
    char * avp_names[] = {"AUTH", "EAP-PAYLOAD", "INTEGRITY ALG", "KEY-ID", "NONCE", "PRF ALG", "RESULT-CODE", "SESSION-LIFETIME", "TERMINATION-CAUSE"};
	
	// All AVP codes are between AUTH and TERMINATIONCAUSE
    if (avp_code >= AUTH_AVP && avp_code <= TERMINATIONCAUSE_AVP) {
        return avp_names[avp_code - 1];
    } else {
		pana_debug("ERROR getAvpName, wrong AVP code (%d)",avp_code);
        return NULL;
    }
}

char * getMsgName(int msg_type) {
    char *pana_msg_type[] = {"PCI", "PANA-Auth", "PANA-Termination", "PANA-Notification"};
	// All MSG types are between PCI and PNA
    if (msg_type >= PCI_MSG && msg_type <= PNA_MSG) {
        return pana_msg_type[msg_type - 1];
    } else {
		pana_debug("ERROR getMsgName, wrong message type (%d)",msg_type);
        return NULL;
    }
}

int isOctetString(int type){
	return (type==AUTH_AVP || type ==EAPPAYLOAD_AVP || type == NONCE_AVP);		
}

int paddingOctetString(int size) {

    int left4byte = size % 4;
    int padding = 0;
    if (left4byte != 0) {
        padding = 4 - left4byte;
    }

    return padding;
}

void debug_msg(pana *hdr){
	#ifdef DEBUG
    fprintf(stderr,"Pana Message Name: %s \n", getMsgName(ntohs(hdr->msg_type)));
    //fprintf(stderr," 0                   1                   2                   3\n");
    //fprintf(stderr," 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n");
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|        Reserved:%d           |          MessageLength: %d      |\n", ntohs(hdr->reserved), ntohs(hdr->msg_length));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|       Flags: ");
    int flags = ntohs(hdr->flags);//R S C A P I
    fprintf(stderr,"%s",(flags & R_FLAG)?"R":"-");
    fprintf(stderr,"%s",(flags & S_FLAG)?"S":"-");
    fprintf(stderr,"%s",(flags & C_FLAG)?"C":"-");
    fprintf(stderr,"%s",(flags & A_FLAG)?"A":"-");
    fprintf(stderr,"%s",(flags & P_FLAG)?"P":"-");
    fprintf(stderr,"%s",(flags & I_FLAG)?"I":"-");
    fprintf(stderr,"         |       MessageType: %d            |\n",  ntohs(hdr->msg_type));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|                     Session Identifier: %#X            |\n", ntohl(hdr->session_id));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|                     Sequence Number: %#X               |\n", ntohl(hdr->seq_number));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");

    int size = ntohs(hdr->msg_length) - sizeof (pana);
    int offset = 0;
    char * msg = (char *) hdr;
    while (size > 0) {
        avp_pana * elmnt = (avp_pana *) (msg + sizeof(pana) + offset);
        debug_avp(elmnt);
        int avance = ntohs(elmnt->length);
        if(isOctetString(ntohs(elmnt->code))){
			avance += paddingOctetString(avance);
		} 
		avance += sizeof(avp_pana);
        size = size - avance;
        offset = offset + avance;
    }
    #endif
}

void debug_avp(avp_pana * datos){
	#ifdef DEBUG
	char * avpname = getAvpName(ntohs(datos->code));
	if(avpname != NULL){
		
		int sizevalue = ntohs(datos->length);
		fprintf(stderr,"AVP Name: %s\n", avpname);
		//fprintf(stderr," 0                   1                   2                   3\n");
		//fprintf(stderr," 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n");
		fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		fprintf(stderr,"|        AVP Code:%d            |           AVP Flags:%d         |\n", ntohs(datos->code), ntohs(datos->flags));
		fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		fprintf(stderr,"|       AVP Length: %d           |       Reserved: %d           |\n", sizevalue, ntohs(datos->reserved));
		fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		fprintf(stderr,"|    Value: ");

		if(ntohs(datos->code) == EAPPAYLOAD_AVP){
			fprintf(stderr," EAP-Payload omitted.");
		}
		/*else if(ntohs(datos->code) == AUTH_AVP){
			fprintf(stderr," AUTH omitted.");
		}*/
		else if (sizevalue > 0 ) {
			for(int i = 0; i< sizevalue; i++){
				fprintf(stderr," %.2X",((*(((char*)datos) + sizeof(avp_pana) + i))&0xFF));
				if (i!=0 && i%16 == 0)
				fprintf(stderr,"\n            ");
			}
		}
		else{
			fprintf(stderr," (none)");
		}
		fprintf(stderr,"\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    }
    #endif
}
