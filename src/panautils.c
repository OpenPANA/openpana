/**
 * @file panautils.c
 * @brief  Contains functions wich performs various helpful actions
 * on the OpenPANA software.
 **/
/*
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

#include "panautils.h"
#include "prf_plus.h"
#include "panamessages.h"

int sendPana(struct sockaddr_in destaddr, char *msg, int sock) {


    if (msg == NULL) { //If no message is provided
		pana_debug("sendPana ERROR NULL message parameter");
        return -1;
    }
    if(sock == 0){
		pana_debug("sendPana ERROR socket it's 0");
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

	pana_debug("Sended to IP: %s , port %d", inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));
	pana_debug("Sended %d bytes to %s", total, inet_ntoa(destaddr.sin_addr));

    if (n == -1) return -1;
    else return total;
}

int checkPanaMessage(pana *msg, pana_ctx *pana_session) {
	/*#ifdef DEBUG
	fprintf(stderr, "DEBUG: MESSAGE TO BE CHECKED\n");
	debug_msg(msg);
	#endif*/
    //Checks pana header fields.
    if (msg->reserved != 0) {
		pana_error("Reserved field is not set to zero. Dropping message");
        return 0;
    }
    short flags = ntohs(msg->flags) & 0XFFFF;
    short msg_type = ntohs(msg->msg_type);
	int session_id = ntohl(msg->session_id);
	
    if ((ntohs(msg->flags) != 0 && ntohs(msg->flags) < I_FLAG) || //The I FLAG is the smallest
            (ntohs(msg->flags) > (I_FLAG | R_FLAG | S_FLAG | C_FLAG | A_FLAG | P_FLAG))) { //0xFC00 is the result of adding all the flags.
        pana_error("Invalid message flags. Dropping message");
        return 0;
    }
    
    if (msg_type < PCI_MSG || msg_type > PNA_MSG) {
		pana_error("Invalid message type. Dropping message");
        return 0;
    }
    
	//Checks session-id  !(sess=0 && PCI)
	if (session_id!=pana_session->session_id && !(session_id==0 && msg_type == PCI_MSG)){
		pana_error("The message session id is not valid. Dropping message");
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
			pana_error("Wrong Request secuence number. Dropping message");
            return 0;
        }
        //Si recibes un request válido, hay que actualizar el número de secuencia para el answer
        pana_session->SEQ_NUMBER = seq_number;
    } else if (msg_type != PCI_MSG) { //No es PCI, es un Answer
		
        if (pana_session->SEQ_NUMBER != seq_number) { //Si se recibe un answer erroneo
			pana_error("Wrong Answer secuence number. Dropping message");
			pana_debug("Values: session -> %d, message -> %d", pana_session->SEQ_NUMBER, seq_number);
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
        data = XMALLOC(char,size);
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
		XFREE(data); //Once its compared, data can be freed
		
        if (i == size) { //If both are the same, the AUTH is correct
			pana_debug("AUTH AVP checked. Correct");
        } else {
			pana_debug("AUTH AVP checked. INCORRECT");
			pana_error("Wrong AUTH AVP value. Dropping message");
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
    
    seed = XMALLOC(char,size);
    
    memcpy(seed, &port, sizeof (short)); //port + ip
    memcpy(seed + sizeof (short), ip, strlen(ip));
    
    result = XMALLOC(char,20);
    
    PRF((u8 *) "session id", 10, (u8*) seed, size, (u8*) result);
    int * point = (int *) result;
    int rc = (*point);
    pana_debug("Session Id %d generated with port %d and ip %s",rc,port,ip);
    XFREE(seed);
    XFREE(result);
    return rc;
}

u8 * generateAUTH(pana_ctx * session) {

    if (session->PaC_nonce == NULL) {
		pana_debug("Unable to generate AUTH. Null PAC_NONCE");
        return NULL;
    } else if (session->PAA_nonce == NULL) {
		pana_debug("Unable to generate AUTH. Null PAA_NONCE");
        return NULL;
    } else if (session->msk_key == NULL) {
		pana_debug("Unable to generate AUTH. Null Msk_key");
        return NULL;
    }else if (session->I_PAR == NULL) {
		pana_debug("Unable to generate AUTH. Null I_PAR");
        return NULL;
    } else if (session->I_PAN == NULL) {
		pana_debug("Unable to generate AUTH. Null I_PAN");
        return NULL;
    }
    else if (session->key_id == NULL || session->key_id_length <=0){
		#ifdef DEBUG
        fprintf(stderr, "DEBUG: Unable to generate AUTH without Key-Id\n");
        #endif
        return NULL;
	}
    pana_debug("Starting AUTH generation");
    /*fprintf(stderr, "DEBUG: PaC Nonce:\n");
    debug_msg((pana*)session->PaC_nonce);
    fprintf(stderr, "DEBUG: PAA Nonce:\n");
    debug_msg((pana*)session->PAA_nonce);
    fprintf(stderr, "DEBUG: MSK Key:\n");
    for(unsigned int i =0; i< session->key_len;i++){
		fprintf(stderr,"%02X",session->msk_key[i]);
	}
    fprintf(stderr,"\n");
    fprintf(stderr, "DEBUG: I_PAN:\n");
    debug_msg((pana*)session->I_PAN);
    fprintf(stderr, "DEBUG: I_PAR:\n");
    debug_msg((pana*)session->I_PAR);
    fprintf(stderr, "DEBUG: Key-ID:\n");
    for(int i =0; i< session->key_id_length;i++){
		fprintf(stderr,"%02X",session->key_id[i]);
	}
    */

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
    sequence = XMALLOC(char,seq_length);
	
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

    XFREE(result);
    result = XMALLOC(char,40); //To get the 320bits result key
	
	/*#ifdef DEBUG
	fprintf(stderr,"DEBUG: PRF Seed is: \n");
	for (int j=0; j<seq_length; j++){
		fprintf(stderr, "%02x ", sequence[j]);
	}
	#endif*/
	
    PRF_plus(2, session->msk_key, session->key_len, (u8*) sequence, seq_length, result);
    
    if (result != NULL) {
		pana_debug("Generated PANA_AUTH_KEY");
    }

    /*int i;
    for (i = 0; i < 40; i++) {
        fprintf(stderr, "%02x ", (u8) result[i]);
    }*/

    XFREE(sequence); //Seed's memory is freed
    return result;
}

int hashAuth(char *msg, char* key, int key_len) {
	//The AVP code (AUTH) to compare with the one in the panaMessage
    char * elmnt = getAvp(msg, AUTH_AVP);
    //debug_avp((avp_pana*)elmnt);
	/*fprintf(stderr,"DEBUG: Key to use: ");
	for (int i =0; i<key_len; i++){
		fprintf(stderr,"%2X ",key[i] & 0xFF);
	}
	fprintf(stderr,"\n");*/
    
    if (elmnt == NULL) //If there's no AUTH return an error
        return 1;
    PRF_plus(1, (u8*) key, key_len, (u8*) msg, ntohs(((pana*)msg)->msg_length), (u8*) (elmnt + sizeof(avp_pana)) );
    return 0; //Everything went better than expected
}

//Add 1 to the current KeyID value
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

    srand(getTime()); //initialize random generator using time
    int key_id_length = KEY_ID_LENGTH; 
    (*global_key_id) = (char *) XMALLOC(char,key_id_length);
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

double getTime(){
	double time;
	
	#ifdef HAVE_GETTIMEOFDAY
		struct timeval tv; 
		gettimeofday(&tv, NULL);
		time = tv.tv_sec;
		time += tv.tv_usec / 1000000.0;
	#else
		time = time(NULL);
	#endif
		
    return time;
}

void waitusec(unsigned int wait){
	waitnano(wait*1000);
}
void waitnano(long wait){
	#ifdef HAVE_NANOSLEEP
		struct timespec req;
		long seconds = 0;
		while(wait > 999999999){//If the limit of nsecs is reached.
			seconds++;
			wait -= 1000000000;
		}
		req.tv_sec=seconds;
		req.tv_nsec=wait;
		nanosleep(&req,NULL);
	#elif HAVE_USLEEP
		usleep(wait/1000);
	#endif
}

void pana_warning (const char *message, ...){
	va_list args;
    fprintf (stderr,"PANA: warning: ");
    va_start( args, message );
    vfprintf( stderr, message, args );
    va_end( args );
    fprintf( stderr, ".\n" );
}

void pana_error (const char *message, ...){
	va_list args;
    fprintf (stderr,"PANA: ERROR: ");
    va_start( args, message );
    vfprintf( stderr, message, args );
    va_end( args );
    fprintf( stderr, ".\n" );
}

void pana_fatal (const char *message, ...){
	va_list args;
    fprintf (stderr,"PANA: FATAL: ");
    va_start( args, message );
    vfprintf( stderr, message, args );
    va_end( args );
    fprintf( stderr, ".\n" );
	exit(EXIT_FAILURE);
}

void pana_debug (const char *message, ...) {
	#ifdef DEBUG
	va_list args;
    fprintf (stderr,"PANA: DEBUG: ");
    va_start( args, message );
    vfprintf( stderr, message, args );
    va_end( args );
    fprintf( stderr, ".\n" );
	#endif
}

// Memory managment wrappers implementation, their headers are in
// include.h

void * xmalloc (size_t num){
  void *new = malloc (num);
  if (!new)
    pana_fatal ("Out of memory");
  return new;
}

void * xrealloc (void *p, size_t num){
  void *new;

  if (!p)
    return xmalloc (num);

  new = realloc (p, num);
  if (!new)
    pana_fatal ("Out of memory");

  return new;
}

void * xcalloc (size_t num, size_t size){
  void *new = xmalloc (num * size);
  #ifdef HAVE_MEMSET
    memset(new,0,num*size);
  #else
	bzero (new, num * size);
  #endif
  return new;
}
