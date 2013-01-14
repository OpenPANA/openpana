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
//#include "state_machines/statemachine.h"
#ifndef ISPRE
	#include "state_machines/session.h"
#endif

#include "panautils.h"
#include "prf_plus.h"

static char * avp_names[] = {"AUTH", "EAP-Payload", "Integrity-Algorithm", "Key-Id", "Nonce", "PRF-Algorithm", "Result-Code", "Session-Lifetime", "Termination-Cause", "PaC-Information", "Relayed-Message"};

/** 
 * Returns the name of the AVP given its code.
 * 
 * @param avp_code AVP code.
 * 
 * @return AVP name. 
 * */
static char * getAvpName(uint16_t avp_code) {
	
	// All AVP codes are between AUTH and Relayed-Message
    if (avp_code >= AUTH_AVP && avp_code <= RELAYEDMESSAGE_AVP) {
        return avp_names[avp_code - 1];
    }
    
	pana_debug("ERROR getAvpName, wrong AVP code (%d)",avp_code);
	return NULL;
}
/**
 * Returns if an AVP is OctetString or not.
 * 
 * @param type AVP code.
 * 
 * @return If the AVP is OctetString.
 * */

static bool isOctetString(uint16_t type){
	return (type==AUTH_AVP || type ==EAPPAYLOAD_AVP || type == NONCE_AVP || type == PACINFORMATION_AVP || type == RELAYEDMESSAGE_AVP);		
}
/**
 * Returns the padding space needed given an OctetString size.
 * 
 * @param size AVP size.
 * 
 * @return Padding needed.
 */
static uint16_t paddingOctetString(uint16_t size) {

    uint16_t left4byte = size % 4;
    uint16_t padding = 0;
    if (left4byte != 0) {
        padding = 4 - left4byte;
    }

    return padding;
}
/**
 * Returns the code of one of the AVP flag appeareances.
 * @param flag AVP flag to identify.
 * @return One of the AVP Codes of an AVP in the flag section.
 * */
static uint16_t identifyAVP(uint16_t flag){
	//the AVP code is identified from the AVP_name using flags    
    if (flag & F_EAPP) {
        return EAPPAYLOAD_AVP;
    } else if (flag & F_INTEG) {
        return INTEGRITYALG_AVP;
    } else if (flag & F_KEYID) {
        return KEYID_AVP;
    } else if (flag & F_NONCE) {
        return NONCE_AVP;
    } else if (flag & F_PRF) {
        return PRFALG_AVP;
    } else if (flag & F_RES) {
        return RESULTCODE_AVP;
    } else if (flag & F_SESS) {
        return SESSIONLIFETIME_AVP;
    } else if (flag & F_TERM) {
        return TERMINATIONCAUSE_AVP;
    }else if (flag & F_AUTH) {
        return AUTH_AVP;
    }
    //Auth avp MUST be the last one in case of multiple avps, that's
    //because when sending a PANA message it has to be the last AVP
    //to include so the hash is created correctly
    pana_debug("identifyAVP: unknown AVP flag %d",flag);
    
    return 0;
}

char * transmissionRelayedMessage (int ip_ver, void *destaddr, char* msg, int sock, void *pacaddr){
	if (ip_ver != 4 && ip_ver != 6){
		pana_error("transmissionRelayedMessage: Unable of using the IP version %d", ip_ver);
		return NULL;
	}
	if (destaddr == NULL || sock == 0){
		pana_error("transmissionRelayedMessage: Invalid communication parameters");
		return NULL;
	}
	if (msg == NULL){
		pana_error("transmissionRelayedMessage: There is no message to be relayed");
		return NULL;
	}

	int msg_size; //Relayed message total size
	int relay_size; //Size of the message contained in the Relayed-Message AVP
	char * position; //Position where to save values.
	
	//The total size is:
	// PANA Header
	//   PaC-Information AVP Header
	//        PaC-Information Value (calculated later) + paddingOctetString
	//   Relayed-Message AVP Header
	//        Relayed-Message Value + paddingOctetString
	msg_size = sizeof(pana) + 2 * sizeof(avp_pana) + ntohs(((pana*)msg)->msg_length) + paddingOctetString( ntohs(((pana*)msg)->msg_length));

	//Now we calculate the PaC-Information Value + paddingOctetString
	if (ip_ver == 4){
		msg_size += (4+2) + paddingOctetString(4+2); //4 octets for IPv4 address, 2 octets for port number;
	}
	else if (ip_ver ==6) {
		msg_size += (16+2) + paddingOctetString(16+2); //16 octets for IPv4 address, 2 octets for port number;
	}

	//Create a buffer with the message size
	char * message = XMALLOC(char, msg_size);
	memset (message, 0, msg_size);
	pana * header = (pana*) message;

	//////Fill the PANA header
	header->msg_length = htons(msg_size);
	header->msg_type = htons(PRY_MSG);
	header->session_id = 0;
	header->seq_number = 0;

	//////Create the PAC-Information AVP
	int avp_size; //Avp_size of the PaC-Information AVP
	avp_pana * elmnt = (avp_pana*) (message+sizeof(pana));
	position = message + sizeof(pana) + sizeof(avp_pana);
	
	if (ip_ver==4){
		avp_size = (4+2) + paddingOctetString(4+2); //4 octets for IPv4 address, 2 octets for port number;

		//Copy the value of the avp
		//Copy the IP address
		memcpy( position, &( ((struct sockaddr_in*) pacaddr)->sin_addr ), sizeof(struct in_addr));
		//Transform & copy the port
		memcpy(position+sizeof(struct in_addr), &( ((struct sockaddr_in*) pacaddr)->sin_port), sizeof(unsigned short) );
	}
	else if (ip_ver==6){
		avp_size = (16+2) + paddingOctetString(16+2);

		//Copy the value of the avp
		//Copy the IP address
		memcpy(position, &( ((struct sockaddr_in6*) pacaddr)->sin6_addr.s6_addr ), 16);
		//Copy the port
		memcpy(position+16, &( ((struct sockaddr_in6*) pacaddr)->sin6_port), sizeof(unsigned short) );
	}
	//Fill the PaC-Information AVP header 
	elmnt->code = htons(PACINFORMATION_AVP);
	elmnt->length = htons(avp_size);


	//////Create the Relayed-Message AVP
	elmnt = (avp_pana*) (message + sizeof(pana) + sizeof(avp_pana) + avp_size);
	//Position, where introduce the Relayed-Message AVP value, iss in the init of the PaC-Information AVP value. So, we need to jump:
	// PaC-Inf AVP value length, Relayed-Message AVP Header length
	position = position + avp_size + sizeof(avp_pana);

	//Fill the Relayed-Message AVP header fields
	elmnt->code = htons(RELAYEDMESSAGE_AVP);
	relay_size = ntohs(((pana*)msg)->msg_length);
	elmnt->length = htons(relay_size + paddingOctetString(relay_size));
	memcpy(position, msg, relay_size);


	//Once the message has been built, it is sended.
	pana_debug("Tx PRY");
	debug_msg ((pana*)message);

	//Build de destaddr struct depending on the IP version used.
	if (ip_ver==4){ //IPv4 is used.
		struct sockaddr_in * dest_addr = (struct sockaddr_in *) destaddr;

		if (0 >= sendPana(*dest_addr, message, sock)) {
			pana_fatal("sendPana");
		}
	}
	else if (ip_ver==6){
		struct sockaddr_in6 * dest_addr = (struct sockaddr_in6 *) destaddr;
	
		if (0 >= sendPana6(*dest_addr, message, sock)) {
			pana_fatal("sendPana");
		}
	}
	return message;
}



#ifndef ISPRE
char * transmissionMessage(char * msgtype, uint16_t flags, uint32_t *sequence_number, uint32_t sess_id, uint16_t avps, int ip_ver, void * destaddr, void **data, int sock, uint8_t msg_relayed) {
//First, the msgtype argument is checked, it must meet certain conditions
	//- Message type must have 3 positions
	//- All messages start with 'P'
	//- The second letter must be:
	// 	'A' -> 3º must be 'R' or 'N'
	// 	'C' -> 3º must be 'I'
	// 	'N' or 'T' -> 3º must be 'A' or 'R'
	// 	1P && ( (2A && (3R || 3N)) || (2C && 3I) || ((2N || 2T) && (3A || R)) || (2R && 3Y) )
	//			is valid, so !() must be ignored
	// If any of those is unmeet, tx will return an error.
	if(strlen(msgtype) != 3 || !( msgtype[0] == 'P' && ( (msgtype[1] == 'A' && (msgtype[2] == 'R' ||
		msgtype[2] == 'N')) || (msgtype[1] == 'C' && msgtype[2] == 'I') || 
		((msgtype[1] == 'N' || msgtype[1] == 'T') && (msgtype[2] == 'A' || 							  msgtype[2] == 'R'))  )    )){
		pana_debug("transmissionMessage ERROR: Invalid Message: %s",msgtype);
		return NULL;
	}
	
	if(sequence_number == NULL){
		pana_error("transmissionMessage: sequence number its NULL");
		return NULL;
	}

	if(ip_ver!=4 && ip_ver!=6){
		pana_error("transmissionMessage: It is not available to send a message over IP version: %d", ip_ver);
	}
	
    if (flags & R_FLAG) { //The R_FLAG mustn't be specified in
        // the parameters, it'll be ignored
        pana_warning("tramsmissionMessage: received R_FLAG as a parameter, it'll be ignored!");
        flags = (flags & !(R_FLAG));
    }

    // The "flags" parameter will be modified in order to end with all the
    // flags that will be needed to the specified type of message
    // For further information see RFC 5191 page 25 section 7

	//See what AVPs will be needed:
	//uint16_t avpsflags = AVPgenerateflags(avps);
	uint16_t avpsflags = avps;


    //Header's values to be included in panaMessage once they're initialized
    uint16_t msg_type = 99;
    uint32_t session_id = sess_id;

    //Different types of messages are identified and initialized
    if(msgtype[1] == 'C'){//msgtype == "PCI" PANA-Client-Initiation, see RFC 5191 7.1
		//The Sequence Number and Session Identifier fields in this
        //message MUST be set to zero (0)
		*(sequence_number) = 0;
        session_id = 0;
        msg_type = PCI_MSG;
        pana_debug("Tx PCI");
	} else if ( msgtype[1] == 'A' ){ //PANA Auth Message see RFC 5191 7.2 & 7.3

        msg_type = PAUTH_MSG;

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

        msg_type = PTERM_MSG;
        
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
        msg_type = PNOTIF_MSG;
        
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
    } else if (msgtype[2] == 'Y') { //PANA-Relay message
		//The Sequence Number and Session Identifier fields in this
        //message MUST be set to zero (0)
		*(sequence_number) = 0;
        session_id = 0;
        msg_type = PRY_MSG;
        //"PaC-Information" AVP must be added to the avp list
		avpsflags = avpsflags | F_PACINF;
		//"Relayed-Message" AVP must be added to the avp list
		avpsflags = avpsflags | F_RLYMSG;
        pana_debug("Tx PRY");
	}
   

    //The memory needed to create the PANA Header is reserved,
    //the memory for the AVPs will be reserved later
    char ** message;
    pana *msg = XCALLOC(pana,1); //The message is set to 0 by default    
    message = (char**) &msg;
    
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

	
	
	#ifdef ISCLIENT
	//Build de destaddr struct depending on the IP version used.
	if (ip_ver==4){ //IPv4 is used.
		struct sockaddr_in * dest_addr = (struct sockaddr_in *) destaddr;

		if (0 >= sendPana(*dest_addr, (char*)msg, sock)) {
			pana_fatal("sendPana");
		}
	}
	else if (ip_ver==6){
		struct sockaddr_in6 * dest_addr = (struct sockaddr_in6 *) destaddr;
	
		if (0 >= sendPana6(*dest_addr, (char*)msg, sock)) {
			pana_fatal("sendPana");
		}
	}
	#endif

	#ifdef ISSERVER
	if (!msg_relayed) {
		//Build de destaddr struct depending on the IP version used.
		if (ip_ver==4){ //IPv4 is used.
			struct sockaddr_in * dest_addr = (struct sockaddr_in *) destaddr;

			if (0 >= sendPana(*dest_addr, (char*)msg, sock)) {
				pana_fatal("sendPana");
			}
		}
		else if (ip_ver==6){
			struct sockaddr_in6 * dest_addr = (struct sockaddr_in6 *) destaddr;
		
			if (0 >= sendPana6(*dest_addr, (char*)msg, sock)) {
				pana_fatal("sendPana");
			}
		}
	}
	#endif

#ifdef AESCRYPTO
	//After sending a PNA message, there should be a pause for the constrained device 
	if ( strcmp ("PNA", msgtype) ==0) {
		usleep(50000);
	}
#endif

	return (char*)msg;
}
#endif

bool existAvp(char * message, uint16_t avp) {
	pana * msg = (pana *) message;
	 //If there's no name
	 //If there's no message
	 //If the message has no value (no AVPs)
    if (avp <= 0 || msg == NULL || msg->msg_length == sizeof (pana)){
        return FALSE;
    }
    
    return (getAvp(message,identifyAVP(avp))!=NULL);
}

#ifndef ISPRE
uint16_t insertAvps(char** message, int avps, void **data) {
	char * msg = *message;
	#ifdef DEBUG
	if (avps == 0){ //If you're not going to insert any avp
		pana_debug("insertAVPs function used without AVP");
		return 0;
	}

    if (msg == NULL) {//If there is no message given
		pana_debug("insertAVPs hasn't got any message, it MUST be used with a valid pana message");
        return 0;
    }
    #else
    if (avps == 0 || msg == NULL){
        return 0;
    }
    #endif
    
    uint16_t totalsize = sizeof(pana);
    uint16_t stride = totalsize;
    char * position = msg;
    avp_pana * elmnt = NULL;
    uint16_t avpsize=0;
    
    //FIXME en los que necesitan data asegurarnos que hay algo
    //para poner y si no hay mostrar error y no generar el AVP
    while (avps != 0){
		
		uint16_t act_avp = identifyAVP(avps);
		uint16_t padding =0;
		uint32_t option =0;
		struct wpabuf * eap_packet = NULL;
		
		//According to RFC 3588: the AVP Length field MUST be set to 12
		//(16 if the ’V’ bit is enabled) when it's an Unsigned32 AVP.
		//But with PANA, the AVP Length field DOES NOT include the header
		//size, so it must be considered.
		
		//First the header and length options are 
		switch (act_avp){
		
			case INTEGRITYALG_AVP:
				avps -= F_INTEG;
				avpsize = sizeof(avp_pana) + INTEG_AVP_VALUE_LENGTH;
				break;
			case KEYID_AVP:
				avps -= F_KEYID;
				avpsize = sizeof(avp_pana) + KEY_ID_LENGTH; 
				//The Key-Id AVP (AVP Code 4) is of type Integer32 and contains an MSK
				//identifier. The MSK identifier is assigned by PAA and MUST be unique
				//within the PANA session.
				// AVP Integer32: (RFC 3588 4.2 )
				//				32 bit signed value, in network byte order.
				break;
				
			case NONCE_AVP:
				avps -= F_NONCE;
				//A random value is generated
				//It's supposed that the PaC and the PAA each are not
				//trusted with regard to the computation of a random nonce
				//A 20 octets random value will be generated
				if (PRF_SUITE == PRF_AES128_CBC)
					avpsize = sizeof(avp_pana) + NONCE_AES_AVP_VALUE_LENGTH;
				else if (PRF_SUITE == PRF_HMAC_SHA1)
					avpsize = sizeof(avp_pana) + NONCE_HMAC_AVP_VALUE_LENGTH;
				break;
			case PRFALG_AVP:
				avps -= F_PRF;
				avpsize = sizeof(avp_pana) + PRF_AVP_VALUE_LENGTH;
				break;
			case RESULTCODE_AVP:
				avps -= F_RES;
				avpsize = sizeof(avp_pana) + RESCODE_AVP_VALUE_LENGTH;
				break;
			case SESSIONLIFETIME_AVP:
				avps -= F_SESS;
				avpsize = sizeof(avp_pana) + SESSLIFETIME_AVP_VALUE_LENGTH;
				break;
			case TERMINATIONCAUSE_AVP:
				avps -= F_TERM;
				avpsize = sizeof(avp_pana) + TERMCAUSE_AVP_VALUE_LENGTH;
				break;
			case EAPPAYLOAD_AVP:
				avps -= F_EAPP;
				//The EAP-Payload AVP (AVP Code 2) is used for encapsulating the actual
				//EAP message that is being exchanged between the EAP peer and the EAP
				//authenticator. The AVP data is of type OctetString.				
				if (data[EAPPAYLOAD_AVP] == NULL) {
					pana_debug("Generating an EAP-Payload AVP without Payload");
				}
				
				//Now eap packet is gonna be built
				eap_packet = (struct wpabuf *) data[EAPPAYLOAD_AVP];

				/*#ifdef DEBUG
				fprintf(stderr,"BEGIN EAP PACKET\n");
				unsigned int i;
				for (i = 0; i < wpabuf_len(eap_packet); i++) {
					fprintf(stderr,"%02x", packet[i]);
				}
				fprintf(stderr,"END EAP PACKET\n");
				#endif*/
				
				avpsize = sizeof(avp_pana) + wpabuf_len(eap_packet);
				break;
			case AUTH_AVP: 	//This is the last one to be added because
							//If the message contains an auth avp,
							//it must be encrypted
				avps -= F_AUTH;
				//The AVP length varies depending on the
				//integrity algorithm used. The AVP data is of type OctetString.
				//AVP value size = 20, to get the 160bits result key
				if (AUTH_SUITE == AUTH_AES_CMAC)
					avpsize = sizeof(avp_pana) + AUTH_AES_AVP_VALUE_LENGTH;
				else if (AUTH_SUITE == AUTH_HMAC_SHA1_160)
					avpsize = sizeof(avp_pana) + AUTH_HMAC_AVP_VALUE_LENGTH;
				break;
			
		}
		
		if(isOctetString(act_avp)){
			padding = paddingOctetString((avpsize - sizeof(avp_pana)));
		}
		
		totalsize += avpsize + padding;
		msg = XREALLOC(char,msg,totalsize);
		
		position = msg + stride;
		elmnt = (avp_pana*) position;
		
		//All AVPs defined in this document MUST have the ’V’ (Vendor) bit cleared.
		elmnt->flags = 0;
		elmnt->reserved = 0; //They MUST be set to zero and ignored by the receiver
		elmnt->length =htons(avpsize - sizeof(avp_pana)); 
		elmnt->code = htons(act_avp);
		
		//Update message values
		switch(act_avp){
			case INTEGRITYALG_AVP:
				//FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
				option = ntohl((uint32_t ) data[INTEGRITYALG_AVP]);
				memcpy(position + sizeof(avp_pana), &option, sizeof (option));
				break;
			case KEYID_AVP:
				//FIXME comprobar el data que haya algo
				memcpy(position + sizeof(avp_pana), data[KEYID_AVP], avpsize - sizeof(avp_pana));
				break;
			case NONCE_AVP:
				srand(getTime()); //initialize random generator using time

				for (uint16_t i = 0; i <= (avpsize - sizeof(avp_pana)); i += sizeof (int)) {
					int random = rand();
					//If we need the whole int value
					if ((i + sizeof (int)) <= (avpsize - sizeof(avp_pana))) {
						memcpy((position + sizeof(avp_pana) + i), &random, sizeof (random));
					} else { //If only a part is needed
						memcpy((position + sizeof(avp_pana) + i), &random, (avpsize - sizeof(avp_pana)) % sizeof (random));
					}
				}
				
				memset(position + avpsize,0,padding);
				break;
			case PRFALG_AVP:
				option = ntohl((uint32_t) data[PRFALG_AVP]);
				memcpy(position + sizeof(avp_pana), &option, sizeof (option));
				break;
			case RESULTCODE_AVP:
				option = ntohl((uint32_t) data[RESULTCODE_AVP]);
				memcpy(position + sizeof(avp_pana), &option, sizeof (uint32_t));			
				break;
			case SESSIONLIFETIME_AVP:
				//FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
				option = ntohl((uint32_t) data[SESSIONLIFETIME_AVP]);
				memcpy(position + sizeof(avp_pana), &option, sizeof (uint32_t));			
				break;
			case TERMINATIONCAUSE_AVP:{
				//FIXME: De momento el servidor siempre manda el hmac_sha1. Ver como se manda una lista de varios
				int * valor = (int *)(position + sizeof(avp_pana));
				*(valor) = ntohs((int) data[TERMINATIONCAUSE_AVP]);
				memcpy(position + sizeof(avp_pana), valor, sizeof (int));
				}
				break;
			case EAPPAYLOAD_AVP:{
				const u8* packet = wpabuf_head(eap_packet);
				memcpy(position + sizeof(avp_pana), packet, wpabuf_len(eap_packet));                
				memset(position + avpsize,0,padding);
				}
				break;
			case AUTH_AVP:
				//Set the value and padding to 0
				memset(position + sizeof(avp_pana),0,avpsize - sizeof(avp_pana) + padding);
				
				//In order to get the complete message to hash, the size value
				//must be updated
				((pana *)msg)->msg_length = htons(totalsize);
				
				//If the message contains an auth avp, it must be hashed
				hashAuth(msg, data[AUTH_AVP], AUTH_KEY_LENGTH);
				break;
		}
		
		stride += avpsize+padding;

	}
	//fprintf(stderr,"Totalsize: %d\n",totalsize);
	//Finally totalsize is changed on PANA message
	((pana *)msg)->msg_length = htons(totalsize);
	//fprintf(stderr,"Totalsize: %d\n",ntohs(((pana *)msg)->msg_length));
	//debug_msg((pana*)msg);
	*message = msg;
	return totalsize;
}
#endif

char * getAvp(char *msg, uint16_t type) {
    char * elmnt = NULL;
    
    //Invalid AVP type or no message
	if(type<AUTH_AVP || type>RELAYEDMESSAGE_AVP || msg == NULL){
		return NULL;
	}
	
    uint16_t size = ntohs(((pana*)msg)->msg_length) - sizeof (pana);
    uint16_t offset = sizeof(pana); //Offset to point to the next AVP
    
    while (size > 0) {//While there are AVPs left
        elmnt = msg + offset; //Pointer to the next AVP
		uint16_t padding = 0;
		uint16_t code = ntohs(((avp_pana *)elmnt)->code);
		if ( code == type) {//If is a match return true
            return elmnt;
        }
        uint16_t length = ntohs(((avp_pana *)elmnt)->length);
        if (isOctetString(code)){
			padding = paddingOctetString(length);
		}
        size = size - sizeof(avp_pana) - length - padding;
        offset = offset + sizeof(avp_pana) + length + padding;
    }

    return NULL; //Not found
}

char * getMsgName(uint16_t msg_type) {
    char *pana_msg_type[] = {"PCI", "PANA-Auth", "PANA-Termination", "PANA-Notification", "PANA-Relay"};
	// All MSG types are between PCI and PRY
    if (msg_type >= PCI_MSG && msg_type <= PRY_MSG) {
        return pana_msg_type[msg_type - 1];
    } 
    
	pana_debug("ERROR getMsgName, wrong message type (%d)",msg_type);
	return NULL;
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
    uint16_t flags = ntohs(hdr->flags);//R S C A P I
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

    uint16_t size = ntohs(hdr->msg_length) - sizeof (pana);
    uint16_t offset = 0;
    char * msg = (char *) hdr;
    while (size > 0) {
        avp_pana * elmnt = (avp_pana *) (msg + sizeof(pana) + offset);
        debug_avp(elmnt);
        uint16_t avance = ntohs(elmnt->length);
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
		
		uint16_t sizevalue = ntohs(datos->length);
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
		else if(ntohs(datos->code) == RELAYEDMESSAGE_AVP){
			fprintf(stderr," Relayed-Message payload omitted.");
		}
		else if (sizevalue > 0 ) {
			for(uint16_t i = 0; i< sizevalue; i++){
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
