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

#include "panautils.h"
#include "prf_plus.h"
#include "panamessages.h"

int sendPana(struct sockaddr_in destaddr, char *msg, int sock) {


    if (msg == NULL) { //If no message is provided
		#ifdef DEBUG
			fprintf(stderr,"ERROR: sendPana mensaje nulo.\n");
		#endif
        return -1;
    }
    if(sock == 0){
		#ifdef DEBUG
			fprintf(stderr,"ERROR: sendPana socket es 0.\n");
		#endif
		return -1;
	}
	

    //****** BUILDING BUFFER TO SEND FROM PANAMESSAGE
    //char * buffer = serializePana(msg); //Where the message is going to be built to be sended
    panaMessage * message = (panaMessage*) msg;
    int len = ntohs(message->header.msg_length); // Pana Message's length
    //*********** END OF BUFFER BUILDING
    //FIXME: Habría que liberar el panaMessage no?

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
    fprintf(stderr,"DEBUG: Enviado a IP: %s , port %d \n", inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));
    fprintf(stderr,"Enviados %d bytes a %s\n", total, inet_ntoa(destaddr.sin_addr));
#endif

    //free(buffer); //Message already sent, memory can be freed

    if (n == -1) return -1;
    else return total;
}

panaMessage * unserializePana(char * buf, int numbytes) {

    panaMessage * msg = NULL;

	//FIXME: Comprobar que numbytes sea suficientes para al menos la
	//cabecera pana.

    msg = calloc(sizeof (panaMessage), 1);
    if (NULL == msg) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }
    memcpy(msg, buf, sizeof (panaHeader));

    //Copying the value field filled with AVP information
    int tam_avps = numbytes - (sizeof (panaHeader));

    if (tam_avps > 0) {
        msg->avp_list = calloc(tam_avps, 1);
        if (NULL == msg->avp_list) {
            fprintf(stderr, "ERROR: Out of memory.\n");
            exit(1);
        }
        memcpy((msg->avp_list), buf + sizeof (panaHeader), tam_avps);
    }
    return msg;
}

char * serializePana(panaMessage *msg) {
    char * buffer = NULL;
    int msg_size = ntohs(msg->header.msg_length);
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Tamaño mensaje %d .\n", msg_size);
#endif
    buffer = calloc(msg_size, sizeof (char)); //Memory needed is allocated
    if (NULL == buffer) {
        fprintf(stderr, "ERROR: Out of memory.\n");
        exit(1);
    }

    memcpy(buffer, msg, sizeof (panaHeader)); //Header is copied
    //Copying value of the message (AVPs)
    memcpy((buffer + sizeof (panaHeader)), msg->avp_list, (msg_size - sizeof (panaHeader)));

    return buffer;
}

int checkPanaMessage(panaMessage *msg, pana_ctx *pana_session) {
    //Checks pana header fields.
    if (msg->header.reserved != 0) {
        fprintf(stderr, "ERROR: Reserved field is not set to zero. Dropping message\n");
        return 0;
    }
    if ((ntohs(msg->header.flags) != 0 && ntohs(msg->header.flags) < 0x0400) || //The I FLAG is the smallest
            (ntohs(msg->header.flags) > 0xFC00)) { //0xFC00 is the result of adding all the flags.
        fprintf(stderr, "ERROR: Invalid message flags. Dropping message\n");
        return 0;
    }
    //FIXME: El campo de tamaño del mensaje puede tomar cualquier valor??
    if (ntohs(msg->header.msg_type) < 1 || ntohs(msg->header.msg_type) > 4) {
        fprintf(stderr, "ERROR: Invalid message type. Dropping message\n");
        return 0;
    }
    
    //Session ID Check, can be disabled in configuration file.
    if(CHECK_SESSID == 1){
		//The port used to generate the session id is:
		short port=0;
	#ifdef ISSERVER
		//The destination port in the server
		port = ntohs(pana_session->eap_ll_dst_addr.sin_port);
	#endif
	#ifdef ISCLIENT
		//The source port in the client
		port = SRCPORT;
	#endif
		
		char * ip = inet_ntoa(pana_session->eap_ll_dst_addr.sin_addr);
		int session_id = generateSessionId(ip, port);
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Puerto: %d, ip: %s\n", port, ip);
		fprintf(stderr,"DEBUG: Comprueba los id: %d<--->%d\n", ntohl(msg->header.session_id), session_id);
		#endif
		if (ntohl(msg->header.session_id)!=session_id && !(ntohl(msg->header.session_id)==0 && ntohs(msg->header.msg_type))){
				fprintf(stderr,"ERROR: The message session id is not valid. Dropping message\n");
				return 0;
		}
	}
	#ifdef DEBUG
	else{
		fprintf(stderr,"DEBUG: No se está comprobando el SessionID, mirar configuración.\n");
	}
	#endif
    //Check sequence numbers
    
    #ifdef DEBUG
	fprintf(stderr, "DEBUG: Secuencia cliente: %d. Secuencia paquete: %d\n", pana_session->SEQ_NUMBER,(ntohl(msg->header.seq_number) - 1));
	#endif
        
    if ((ntohs(msg->header.flags) & R_FLAG) == R_FLAG) { //Request msg
        //Si eres el cliente, compruebas que antes tenías o un 0 (del pci)
        //o un numero menos del que se ha recibido.
        //Aunque en el servidor no se va a dar nunca el 0, puede suceder con el PCI en el cliente
       
        if (pana_session->SEQ_NUMBER != 0 && pana_session->SEQ_NUMBER != (ntohl(msg->header.seq_number) - 1)) {
            fprintf(stderr, "ERROR: Wrong Request secuence number. Dropping message.\n");
            return 0;
        }

        //Si recibes un request válido, hay que actualizar el número de secuencia para el answer
        //FIXME: Esto se haría después del AUTH?
        pana_session->SEQ_NUMBER = (ntohl(msg->header.seq_number));
    } else if (ntohs(msg->header.msg_type) != PCI_MSG) { //No es PCI, es un Answer
		
        if (pana_session->SEQ_NUMBER != ntohl(msg->header.seq_number)) { //Si se recibe un answer erroneo
			fprintf(stderr, "ERROR: Wrong Answer secuence number. Dropping message.\n");
            return 0;
        }
    }

    //After checking the sequence numbers, the AUTH avp value is checked if found
    //FIXME: Sólo comprobar si está autenticado, si no está correcto se descarta
    //Check if it contains the Auth AVP and checks it
    if (existAvp(msg, "AUTH")) {
		if (existAvp(msg, "Result-Code")) return TRUE; //FIXME: Hay que comprobar que sea un eap-success 
        char *data; //It will contain the auth avp value
        int size; //Size of the AVP Auth if found
        //The AVP code (Auth = 1) to compare with the one in the panaMessage
        avp * elmnt = getAvp(msg, AUTH_AVP);

        //Now, avp elmnt points to auth avp
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: me guardo el valor recibido del AUTH avp. \n");
        #endif
        size = ntohs(elmnt->avp_length);
        data = malloc(size * sizeof (char));
        if(data == NULL){
			fprintf(stderr,"Out of memory\n");
			exit(1);
		}
        memcpy(data, &(elmnt->value), size);

        //Once the old AUTH is saved, we try to recalculate it
        //again to see if it fits
        memset(&(elmnt->value), 0, size); //Auth value set to 0

        //FIXME: Aquí debería verse si el cryptauth devuelve 1
        //En ese caso el auth es erróneo directamente y se descarta?
        cryptAuth(msg, pana_session->avp_data[1], 40);

        //The original AUTH value is compared with the new one
        char *newAuth = (char *) &(elmnt->value);

        int i = 0;
        for (i = 0; i < size; i++) {
            if (newAuth[i] != data[i])
                break;
        }
		free(data); //Once its compared, data can be freed
		
        if (i == size) { //If both are the same, the AUTH is correct
            #ifdef DEBUG
            fprintf(stderr, "DEBUG: Comprobado el AUTH avp. Es correcto\n");
            #endif
        } else {
        #ifdef DEBUG
            fprintf(stderr, "DEBUG: Comprobado el AUTH avp. NO es correcto\n");
        #endif
            return FALSE; //Invalid, message is ignored
        }
    }
    return TRUE;
}

int cryptAuth(panaMessage *msg, char* key, int key_len) {

    avp * elmnt = getAvp(msg, AUTH_AVP); //The AVP code (AUTH) to compare with the one in the panaMessage
    if (elmnt == NULL) //Caso de que no haya ningun AUTH
        return 1;
	u8 * serializedMessage = (u8*) serializePana(msg);
    PRF_plus(1, (u8*) key, key_len, serializedMessage, ntohs(msg->header.msg_length), (u8*)&(elmnt->value));
    #ifdef DEBUG
    fprintf(stderr,"DEBUG: Ha encriptado el auth avp\n");
    #endif
	free(serializedMessage);
    return 0; //Everything went better than expected
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
    fprintf(stderr,"DEBUG: Generado session id %d, con puerto %d e ip %s\n",rc,port,ip);
    #endif
    free(seed);
    free(result);
    return rc;
}

void debug_print_avp(avp *elmnt) {
    #ifdef DEBUG
	char * avpname = getAvpName(ntohs(elmnt->avp_code));
	if(avpname != NULL){
		fprintf(stderr,"AVP Name: %s\n", avpname);
		fprintf(stderr," 0                   1                   2                   3\n");
		fprintf(stderr," 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n");
		fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		fprintf(stderr,"|        AVP Code:%d            |           AVP Flags:%d         |\n", ntohs(elmnt->avp_code), ntohs(elmnt->avp_flags));
		fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		fprintf(stderr,"|       AVP Length: %d           |       Reserved: %d           |\n", ntohs(elmnt->avp_length), ntohs(elmnt->reserved));
		fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		if (ntohs(elmnt->avp_length) > 0) {
			//fprintf(stderr,"|    Value: %s\n",elmnt->value);
			//fprintf(stderr,"|    Value:\n");
			fprintf(stderr,"+-+-+-+-+-+-+-+-+\n");
		}
		fprintf(stderr,"|    Value:\n");
		fprintf(stderr,"\n+-+-+-+-+-+-+-+-+\n");
    }
    #endif
}

void debug_print_message(panaMessage *msg) {
    #ifdef DEBUG
    panaHeader hdr = msg->header;
    fprintf(stderr,"Pana Message Name: %s \n", getMsgName(ntohs(hdr.msg_type)));
    fprintf(stderr," 0                   1                   2                   3\n");
    fprintf(stderr," 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n");
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|        Reserved:%d          |           MessageLength: %d      |\n", ntohs(hdr.reserved), ntohs(hdr.msg_length));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|       Flags: %hx           |       MessageType: %d            |\n", ntohs(hdr.flags), ntohs(hdr.msg_type));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|                     Session Identifier: %d                   |\n", ntohl(hdr.session_id));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    fprintf(stderr,"|                     Sequence Number: %d                   |\n", ntohl(hdr.seq_number));
    fprintf(stderr,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");

    int size = ntohs(hdr.msg_length) - sizeof (panaHeader);
    int offset = 0;
    //printf("DEBUG: debugmessage Value=%s \n", (msg->avp_list + 4 * sizeof (short)));

    while (size > 0) {
        avp * elmnt = (avp *) (msg->avp_list + offset);
        debug_print_avp(elmnt);
        size = size - (4 * sizeof (short) +ntohs(elmnt->avp_length));
        offset = offset + (4 * sizeof (short) +ntohs(elmnt->avp_length));
    }
    #endif
}

char * getAvpName(int avp_code) {
    char * avp_names[] = {"AUTH", "EAP-PAYLOAD", "INTEGRITY ALG", "KEY-ID", "NONCE", "PRF ALG", "RESULT-CODE", "SESSION-LIFETIME", "TERMINATION-CAUSE"};

    if (avp_code > 0 && avp_code < 10) {
        return avp_names[avp_code - 1];
    } else {
    #ifdef DEBUG
        fprintf(stderr, "DEBUG: ERROR getAvpName, código de AVP (%d) incorrecto.\n",avp_code);
    #endif
        return NULL;
    }
}

char * getMsgName(int msg_type) {
    //TODO: Añadirle que reciba un short flags y devuelva si es Answer o Request.
    char *pana_msg_type[] = {"PCI", "PANA-Auth", "PANA-Termination", "PANA-Notification"};

    if (msg_type > 0 && msg_type < 5) {
        return pana_msg_type[msg_type - 1];
    } else {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: ERROR getMsgName, código de mensaje (%d) incorrecto.\n",msg_type);
        #endif
        return NULL;
    }
}

u8 * extractNonce(char * message) {
    //FIXME: esto enlazaría con sacar un getAvp
    int type = NONCE_AVP; //The AVP code (Nonce) to compare with the one in the panaMessage
    u8 * result = NULL;
    avp *elmnt = NULL;

    //All the avp_codes in the panaMessage are compared with the one given
    //If there's no name

    panaHeader * msg = (panaHeader *) message;
    short size = ntohs(msg->msg_length);
    //fprintf(stderr,"Tamaño pana: %d \n",size);
    short offset = 0; //Offset to point to the next AVP

    while (size > 0) {//While there are AVPs left
        char * nextavp = (message + sizeof (panaHeader) + offset);
        elmnt = (avp *) (nextavp); //Pointer to the next AVP
        int padding = 0;
        
        debug_print_avp(elmnt);
        //fprintf(stderr, "DEBUG: Sigue en el generateAUTH bien.\n");
        if (ntohs(elmnt->avp_code) == type) {//If is a match return true
            //eap_packet = elmnt->value;
            //fprintf(stderr, "DEBUG: genial!!!.\n");
            //fprintf(stderr,"AVP_LENGTH: %d",ntohs(elmnt->avp_length));
            result = (u8 *)&(elmnt->value);
            break;
        }
        if (isOctetString(ntohs(elmnt->avp_code))){
			padding = paddingOctetString(ntohs(elmnt->avp_length));
		}
        size = size - (4 * sizeof (short) +ntohs(elmnt->avp_length)) - padding;
        offset = offset + (4 * sizeof (short) +ntohs(elmnt->avp_length)) + padding;
    }
    return result;
}

u8 * generateAUTH(pana_ctx * session) {

    if (session->PaC_nonce == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: No se ha podido generar la clave. PAC_NONCE nulo\n");
        #endif
        return NULL;
    } else if (session->PAA_nonce == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: No se ha podido generar la clave. PAA_NONCE nulo\n");
        #endif
        return NULL;
    } else if (session->msk_key == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: No se ha podido generar la clave. Msk_key nulo\n");
        #endif
        return NULL;
    }else if (session->I_PAR == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: No se ha podido generar la clave. I_PAR nulo\n");
        #endif
        return NULL;
    } else if (session->I_PAN == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "DEBUG: No se ha podido generar la clave. I_PAN nulo\n");
        #endif
        return NULL;
    }
    #ifdef DEBUG
    fprintf(stderr, "DEBUG: Función generateAUTH, con todos los datos necesarios.\n");
    #endif

    panaHeader * msg;

    u8 * result = NULL; //Result to save the prf result value
    u8 *pac_nonce; //Nonce avp from the pac
    u8 *paa_nonce; //Nonce avp from the paa
    int i_par_length; //PAR message length
    int i_pan_length; //PAN message length
    char *sequence; //Seed secuence to use in prf function

    //First of all calculates the sequence's length
    u16 seq_length = 9; // The string "IETF PANA" length

    msg = (panaHeader *) (session->I_PAR);
    i_par_length = ntohs(msg->msg_length);
    seq_length += i_par_length; // The I_PAR length

    msg = (panaHeader *) (session->I_PAN);
    i_pan_length = ntohs(msg->msg_length);
    seq_length += i_pan_length; // The I_PAN length

    //Get both nonce avps
    //FIXME: Guardar el NONCE como el Key-Id, no haria falta tanto recorrido
    pac_nonce = extractNonce(session->PaC_nonce);
    paa_nonce = extractNonce(session->PAA_nonce);

    //FIXME: Quitar el numero magico 20
    seq_length += (20 * sizeof (char)); //pac_nonce length
    seq_length += (20 * sizeof (char)); //paa_nonce length

    seq_length += session->key_id_length;

    sequence = malloc(seq_length * sizeof (char));
    if(sequence == NULL){
		fprintf(stderr,"ERROR: Out of memory\n");
		exit(1);
	}
    //Once the memory is correctly reserved and allocated, we start copying
    //The values to form the seed's secuence

    seq_length = 0; // It carries on the completed sequence's lenght 

    char ietf[10] = "IETF PANA";
    memcpy(sequence, ietf, strlen(ietf)); //FIXME numero magico

    seq_length += strlen(ietf);


    memcpy(sequence + seq_length, session->I_PAR, i_par_length);
    seq_length += i_par_length;
    memcpy(sequence + seq_length, session->I_PAN, i_pan_length);
    seq_length += i_pan_length;

    //FIXME El tamaño del nonce puede no ser 20?
    memcpy(sequence + seq_length, pac_nonce, (20 * sizeof (char)));
    seq_length += (20 * sizeof (char));
    memcpy(sequence + seq_length, paa_nonce, (20 * sizeof (char)));
    seq_length += (20 * sizeof (char));
	
	
	//Generates the Key-Id 
	if(session->key_id != NULL){
		free(session->key_id);
	}
	session->key_id = malloc(session->key_id_length);
	generateKeyID(session->key_id, session->key_id_length, session->msk_key, session->key_len);
	
    memcpy(sequence + seq_length, session->key_id, session->key_id_length);
    seq_length += session->key_id_length;


    if (result != NULL) free(result);

    result = malloc(40); //To get the 320bits result key
	if(result == NULL){
		fprintf(stderr,"ERROR: Out of memory\n");
		exit(1);
	}
	
	/*
	#ifdef DEBUG
	fprintf(stderr,"DEBUG: PRF Seed is: \n");
	for (int j=0; j<seq_length; j++){
		fprintf(stderr, "%02x ", sequence[j]);
	}
	#endif
	*/
    PRF_plus(2, session->msk_key, session->key_len, (u8*) sequence, seq_length, result);
    
    /*#ifdef DEBUG
    if (result != NULL) {
        fprintf(stderr,"DEBUG: Generated PANA_AUTH_KEY.\n");
    }

    int i;
    for (i = 0; i < 40; i++) {
        fprintf(stderr, "%02x ", (u8) result[i]);
    }
    #endif
    */
    free(sequence); //Seed's memory is freed
    return result;
}

avp * getAvp(panaMessage *msg, int type) {
    avp * elmnt = NULL;

    int size = ntohs(msg->header.msg_length) - sizeof (panaHeader);
    int offset = 0; //Offset to point to the next AVP
    while (size > 0) {//While there are AVPs left
        elmnt = (avp *) (msg->avp_list + offset); //Pointer to the next AVP
		int padding = 0;
		
        if (ntohs(elmnt->avp_code) == type) {//If is a match return true
            return elmnt;
        }
        
        if (isOctetString(ntohs(elmnt->avp_code))){
			padding = paddingOctetString(ntohs(elmnt->avp_length));
		}
        size = size - (4 * sizeof (short) +ntohs(elmnt->avp_length)) - padding;
        offset = offset + (4 * sizeof (short) +ntohs(elmnt->avp_length)) + padding;
    }

    return elmnt;
}


int isOctetString(int type){
	return (type==AUTH_AVP || type ==EAPPAYLOAD_AVP || type == NONCE_AVP);		
}

int generateKeyID (char* key_id, int key_id_length, u8* msk_key, unsigned int msk_len) {
    /* FIXME El el cliente, el key-id debe generarse o no? creo que hay que cogerlo del
     * paquete que envía el PAA ya que el identificador te lo da él. Así se consigue
     * poder utilizar implementaciones que generan el key-id de forma distinta sin problemas, no?.
     * */
    for (int i = 0; i <= key_id_length; i += msk_len) {
        //If we need the whole int value
        if ((i + msk_len) <= key_id_length) {
            memcpy((key_id + i), msk_key, msk_len);
        } else { //If only a part is needed
            memcpy((key_id + i), msk_key, (key_id_length % msk_len));
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
