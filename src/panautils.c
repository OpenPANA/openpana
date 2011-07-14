/*
 *  panautils.c
 *  
 * 	Contains functions wich performs differents helpful actions on PANA
 * 	messages.
 *
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 18/10/10.
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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include "panautils.h"
#include "prf_plus.h"
#include "panamessages.h"

int sendPana(struct sockaddr_in destaddr, char *msg, int sock) {


    if (msg == NULL) { //If no message is provided
		#ifdef DEBUG
			fprintf(stderr,"ERROR: sendPana NULL message parameter.\n");
		#endif
        return -1;
    }
    if(sock == 0){
		#ifdef DEBUG
			fprintf(stderr,"ERROR: sendPana socket it's 0.\n");
		#endif
		return -1;
	}
	
    int len = ntohs(((pana*)msg)->msg_length); // Pana Message's length
    
    //int sock;
    struct sockaddr_in su_addr; // Destination address
    

    struct sockaddr_in mi_addr;
    mi_addr.sin_family = AF_INET;

    #ifdef ISCLIENT
    mi_addr.sin_port = ntohs(SRCPORT);
    #endif
    #ifdef ISSERVER
    mi_addr.sin_port = ntohs(destaddr.sin_port);
    #endif
    mi_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(mi_addr.sin_zero), '\0', 8);

    //FIXME: Se podría coger directamente la estructura del contexto pana?
    su_addr.sin_family = AF_INET;
    su_addr.sin_port = destaddr.sin_port;
    su_addr.sin_addr.s_addr = destaddr.sin_addr.s_addr;
    memset(&(su_addr.sin_zero), '\0', 8);

    int total = 0; // Total bytes sended
    int n = 0;
    int bytesleft = len;
    while (total < len) {
        n = sendto(sock, msg + total, bytesleft, 0,
                (struct sockaddr *) & su_addr, sizeof (struct sockaddr));
        if (n == -1) {
            break;
        } //Send failure
        total += n;
        bytesleft -= n;
    }

#ifdef DEBUG
    fprintf(stderr,"DEBUG: Sended to IP: %s , port %d \n", inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));
    fprintf(stderr,"PANA: Sended %d bytes to %s\n", total, inet_ntoa(destaddr.sin_addr));
#endif

    if (n == -1) return -1;
    else return total;
}

int checkPanaMessage(pana *msg, pana_ctx *pana_session) {
	/*#ifdef DEBUG
	fprintf(stderr, "DEBUG: MESSAGE TO BE CHECKED\n");
	debug_pana(msg);
	#endif*/
    //Checks pana header fields.
    if (msg->reserved != 0) {
        fprintf(stderr, "ERROR: Reserved field is not set to zero. Dropping message\n");
        return 0;
    }
    short flags = ntohs(msg->flags) & 0XFFFF;
    short msg_type = ntohs(msg->msg_type);
	int session_id = ntohl(msg->session_id);
	
    if ((ntohs(msg->flags) != 0 && ntohs(msg->flags) < I_FLAG) || //The I FLAG is the smallest
            (ntohs(msg->flags) > (I_FLAG | R_FLAG | S_FLAG | C_FLAG | A_FLAG | P_FLAG))) { //0xFC00 is the result of adding all the flags.
        fprintf(stderr, "ERROR: Invalid message flags. Dropping message\n");
        return 0;
    }
    
    if (msg_type < PCI_MSG || msg_type > PNA_MSG) {
        fprintf(stderr, "ERROR: Invalid message type. Dropping message\n");
        return 0;
    }
    
	//Checks session-id  !(sess=0 && PCI)
	if (session_id!=pana_session->session_id && !(session_id==0 && msg_type == PCI_MSG)){
			fprintf(stderr,"ERROR: The message session id is not valid. Dropping message\n");
			return 0;
	}
	//FIXME no debería actualizarse el seq-number hasta comprobar auth
	//Check sequence numbers
	int seq_number = ntohl(msg->seq_number);
    if (flags & R_FLAG) { //Request msg
        //Si es un request, compruebas qué antes tenías o un 0 (del pci)
        //o un número menos del que se ha recibido.
        //Aunque en el servidor no se va a dar nunca el 0, puede suceder con el PCI en el cliente
        
        if (pana_session->SEQ_NUMBER != 0 && pana_session->SEQ_NUMBER != ( seq_number - 1)) {
            fprintf(stderr, "ERROR: Wrong Request secuence number. Dropping message.\n");
            return 0;
        }
        //Si recibes un request válido, hay que actualizar el número de secuencia para el answer
        pana_session->SEQ_NUMBER = seq_number;
    } else if (msg_type != PCI_MSG) { //No es PCI, es un Answer
		
        if (pana_session->SEQ_NUMBER != seq_number) { //Si se recibe un answer erroneo
			fprintf(stderr, "ERROR: Wrong Answer secuence number. Dropping message.\n");
            return 0;
        }
    }
    
    //Then the AUTH avp value is checked if found
    //FIXME: Sólo comprobar si está autenticado (hay una PANA SA), si no está correcto se descarta
    //Check if it contains the Auth AVP and checks it
	char * avpbytes = getAvp((char*)msg, AUTH_AVP);
    if (avpbytes != NULL) {//if existsAvp(AUTH)
		if (existAvp((char*)msg, "Result-Code")) return TRUE; //FIXME: Hay que comprobar que sea un eap-success 
        char *data; //It will contain the auth avp value
        int size; //Size of the AVP Auth if found
        //The AVP code (Auth = 1) to compare with the one in the panaMessage
        avp_pana * elmnt = (avp_pana*) avpbytes ;

        //Now, avp elmnt points to auth avp
        size = ntohs(elmnt->length);
        data = malloc(size * sizeof (char));
        if(data == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
		//fprintf(stderr,"AUTH_AVP salvado\n");
		//debug_avp(elmnt);
        memcpy(data, avpbytes + sizeof(avp_pana), size);

        //Once the old AUTH is saved, we try to recalculate it
        //again to see if it fits
        memset(avpbytes + sizeof(avp_pana), 0, size); //Auth value set to 0

        //If the AUTH value cannot be hashed, its an error
        if(hashAuth((char*)msg, pana_session->avp_data[AUTH_AVP], 40)){
			return FALSE; //Auth AVP not found
		}

        //The original AUTH value is compared with the new one
        char *newAuth = avpbytes + sizeof(avp_pana);
		//fprintf(stderr,"AUTH_AVP nuevo\n");
		//debug_avp(elmnt);
        int i = 0;
        for (i = 0; i < size; i++) {
            if (newAuth[i] != data[i])
                break;
        }
		free(data); //Once its compared, data can be freed
		
        if (i == size) { //If both are the same, the AUTH is correct
            #ifdef DEBUG
            fprintf(stderr, "DEBUG: AUTH AVP checked. Correct\n");
            #endif
        } else {
        #ifdef DEBUG
            fprintf(stderr, "DEBUG: AUTH AVP checked. INCORRECT\n");
        #endif
            return FALSE; //Invalid, message is ignored
        }
    }
    
    
    
    return TRUE;
}

int generateSessionId(char * ip, short port) {
	//The seed to generate the sessionId will be port + ip
    char * seed = NULL; //To create the seed
    int size = sizeof (short) +strlen(ip);
    char * result = NULL; //To store the result
    
    seed = malloc(size * sizeof (char));
    if (NULL == seed) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }
    
    memcpy(seed, &port, sizeof (short)); //port + ip
    memcpy(seed + sizeof (short), ip, strlen(ip));
    
    result = malloc(20 * sizeof (char));
    if (NULL == result) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }
    
    PRF((u8 *) "session id", 10, (u8*) seed, size, (u8*) result);
    int * point = (int *) result;
    int rc = (*point);
    #ifdef DEBUG
    fprintf(stderr,"DEBUG: Session Id %d generated withport %d and ip %s\n",rc,port,ip);
    #endif
    free(seed);
    free(result);
    return rc;
}

char * getAvpName(int avp_code) {
    char * avp_names[] = {"AUTH", "EAP-PAYLOAD", "INTEGRITY ALG", "KEY-ID", "NONCE", "PRF ALG", "RESULT-CODE", "SESSION-LIFETIME", "TERMINATION-CAUSE"};
	
	// All AVP codes are between AUTH and TERMINATIONCAUSE
    if (avp_code >= AUTH_AVP && avp_code <= TERMINATIONCAUSE_AVP) {
        return avp_names[avp_code - 1];
    } else {
    #ifdef DEBUG
        fprintf(stderr, "DEBUG: ERROR getAvpName, wrong AVP code (%d).\n",avp_code);
    #endif
        return NULL;
    }
}

char * getMsgName(int msg_type) {
    char *pana_msg_type[] = {"PCI", "PANA-Auth", "PANA-Termination", "PANA-Notification"};
	// All MSG types are between PCI and PNA
    if (msg_type >= PCI_MSG && msg_type <= PNA_MSG) {
        return pana_msg_type[msg_type - 1];
    } else {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: ERROR getMsgName, wrong message type (%d).\n",msg_type);
        #endif
        return NULL;
    }
}

u8 * generateAUTH(pana_ctx * session) {

    if (session->PaC_nonce == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH. Null PAC_NONCE\n");
        #endif
        return NULL;
    } else if (session->PAA_nonce == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH. Null PAA_NONCE\n");
        #endif
        return NULL;
    } else if (session->msk_key == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH. Null Msk_key\n");
        #endif
        return NULL;
    }else if (session->I_PAR == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH. Null I_PAR\n");
        #endif
        return NULL;
    } else if (session->I_PAN == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH. Null I_PAN\n");
        #endif
        return NULL;
    }
    else if (session->key_id == NULL || session->key_id_length <=0){
		#ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH without Key-Id\n");
        #endif
        return NULL;
	}
    #ifdef DEBUG
    fprintf(stderr, "DEBUG: Starting AUTH generation.\n");
    /*fprintf(stderr, "DEBUG: PaC Nonce:\n");
    debug_pana((pana*)session->PaC_nonce);
    fprintf(stderr, "DEBUG: PAA Nonce:\n");
    debug_pana((pana*)session->PAA_nonce);
    fprintf(stderr, "DEBUG: MSK Key:\n");
    for(unsigned int i =0; i< session->key_len;i++){
		fprintf(stderr,"%02X",session->msk_key[i]);
	}
    fprintf(stderr,"\n");
    fprintf(stderr, "DEBUG: I_PAN:\n");
    debug_pana((pana*)session->I_PAN);
    fprintf(stderr, "DEBUG: I_PAR:\n");
    debug_pana((pana*)session->I_PAR);
    fprintf(stderr, "DEBUG: Key-ID:\n");
    for(int i =0; i< session->key_id_length;i++){
		fprintf(stderr,"%02X",session->key_id[i]);
	}
    */
    #endif

    pana * msg;

    u8 * result = NULL; //Result to save the prf result value
    u8 *pac_nonce; //Nonce avp from the pac
    u8 *paa_nonce; //Nonce avp from the paa
    int i_par_length; //PAR message length
    int i_pan_length; //PAN message length
    char *sequence; //Seed secuence to use in prf function
	char ietf[10] = "IETF PANA"; //String "IETF PANA" is part of the seed
	
	//The PANA_AUTH_KEY is derived from the available MSK, and it is used
	//to integrity protect PANA messages. The PANA_AUTH_KEY is computed in
	//the following way:
	//		PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|
	//										PaC_nonce|PAA_nonce|Key_ID)

    //First of all calculates the sequence's length
    u16 seq_length = 9; // The string "IETF PANA" length

    msg = (pana *) (session->I_PAR);
    i_par_length = ntohs(msg->msg_length);
    seq_length += i_par_length; // The I_PAR length

    msg = (pana *) (session->I_PAN);
    i_pan_length = ntohs(msg->msg_length);
    seq_length += i_pan_length; // The I_PAN length
	
    pac_nonce = (u8*) getAvp(session->PaC_nonce,NONCE_AVP);
    paa_nonce = (u8*) getAvp(session->PAA_nonce,NONCE_AVP);
    int paa_nonce_length = ntohs(((avp_pana*)pac_nonce)->length);
    int pac_nonce_length = ntohs(((avp_pana*)paa_nonce)->length);
    
    seq_length += pac_nonce_length; 
    seq_length += paa_nonce_length;

    seq_length += session->key_id_length;
	//fprintf(stderr,"DEBUG: antes malloc seq_length\n");
    sequence = malloc(seq_length * sizeof (char));
    if(sequence == NULL){
		fprintf(stderr,"ERROR: Out of memory\n");
		exit(1);
	}
	
    //Once the memory is correctly reserved and allocated, we start copying
    //The values to form the seed's secuence
    seq_length = 0; // It carries on the completed sequence's lenght 

    memcpy(sequence, ietf, strlen(ietf));

    seq_length += strlen(ietf);

    memcpy(sequence + seq_length, session->I_PAR, i_par_length);
    seq_length += i_par_length;
    memcpy(sequence + seq_length, session->I_PAN, i_pan_length);
    seq_length += i_pan_length;

	//Copies the value of the Nonces
    memcpy(sequence + seq_length, pac_nonce + sizeof(avp_pana), pac_nonce_length);
    seq_length += pac_nonce_length;
    memcpy(sequence + seq_length, paa_nonce + sizeof(avp_pana), paa_nonce_length);
    seq_length += paa_nonce_length;
	
	//Copies Key-Id
    memcpy(sequence + seq_length, session->key_id, session->key_id_length);
    seq_length += session->key_id_length;

    if (result != NULL) free(result);
    result = malloc(40); //To get the 320bits result key
	if(result == NULL){
		fprintf(stderr,"ERROR: Out of memory\n");
		exit(1);
	}
	
	#ifdef DEBUG
	/*fprintf(stderr,"DEBUG: PRF Seed is: \n");
	for (int j=0; j<seq_length; j++){
		fprintf(stderr, "%02x ", sequence[j]);
	}*/
	#endif
	
    PRF_plus(2, session->msk_key, session->key_len, (u8*) sequence, seq_length, result);
    
    #ifdef DEBUG
    if (result != NULL) {
        fprintf(stderr,"DEBUG: Generated PANA_AUTH_KEY.\n");
    }

    /*int i;
    for (i = 0; i < 40; i++) {
        fprintf(stderr, "%02x ", (u8) result[i]);
    }*/
    #endif

    free(sequence); //Seed's memory is freed
    return result;
}

int hashAuth(char *msg, char* key, int key_len) {
	//The AVP code (AUTH) to compare with the one in the panaMessage
    char * elmnt = getAvp(msg, AUTH_AVP);
    //debug_avp((avp_pana*)elmnt);
    #ifdef DEBUG
	/*fprintf(stderr,"DEBUG: Key to use: ");
	for (int i =0; i<key_len; i++){
		fprintf(stderr,"%2X ",key[i] & 0xFF);
	}
	fprintf(stderr,"\n");*/
    #endif
    
    if (elmnt == NULL) //If there's no AUTH return an error
        return 1;
    PRF_plus(1, (u8*) key, key_len, (u8*) msg, ntohs(((pana*)msg)->msg_length), (u8*) (elmnt + sizeof(avp_pana)) );
    return 0; //Everything went better than expected
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


int isOctetString(int type){
	return (type==AUTH_AVP || type ==EAPPAYLOAD_AVP || type == NONCE_AVP);		
}

//Añade 1 al valor actual del KeyId
void increase_one(char *value, int length) {
	
    int i;	
    int increased = 0;
    for (i = length - 1; (i >= 0 && increased == 0); i--) {
        if (value[i] != 0xff) {
            increased = 1;
            value[i] += 1;
        } else {
            value[i] = 0x00;
        }
    }
    //If value is 0xfffff...
    if (i == -1) value[length - 1] = 0x01;
}

int generateRandomKeyID (char** global_key_id) {
    struct timeval seed;
    gettimeofday(&seed, NULL);
    srand(seed.tv_usec); //initialize random generator using usecs
    int key_id_length = 4; //FIXME: shouldn't be here?
    (*global_key_id) = (char *) malloc(key_id_length * (sizeof (char)));
    for (int i = 0; i <= key_id_length; i += sizeof (int)) {
        int random = rand();
        //If we need the whole int value
        if ((i + sizeof (int)) <= key_id_length) {
            memcpy(((*global_key_id) + i), &random, sizeof (random));
        } else { //If only a part is needed
            memcpy(((*global_key_id) + i), &random, (key_id_length % sizeof (random)));
        }
    }
    return 0;
}

int paddingOctetString(int size) {

    int left4byte = size % 4;
    int padding = 0;
    if (left4byte != 0) {
        padding = 4 - left4byte;
    }

    return padding;
}
void debug_pana(pana *hdr){
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
    //printf("DEBUG: debugmessage Value=%s \n", (msg->avp_list + 4 * sizeof (short)));
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

int Hex2Dec (char * value, int length) {
	int res = 0;
	int j=0;
	int number;

	for (int i =(length-1); i>=0; i--){
		number = (int)value[i];
		res = res + number * ((int) pow(16,j));
		j++;
	}
	return res;
}
