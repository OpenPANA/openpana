/*
 *  panautils.h
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
 *  https://sourceforge.net/projects/openpana/
 */

#ifndef PANAUTILS_H
#define PANAUTILS_H

#include "panamessages.h"
#include "./state_machines/session.h"

#define PANAPORT 716
#define MAXSIZEUDP 1280

//Devuelve el numero de bytes enviados o -1 en caso de error
//FIXME: Hace un envío normal y corriente, se podría eliminar la función?
int sendPana(struct sockaddr_in destaddr, char *msg, int sock);

 /** 
  * Returns if a PANA message is correct. Checks the header (flags, reserved field, messages types),
  * sequence numbers, session identificators and AUTH value if any. 
  * 
  * @param msg PANA message.
  * @param pana_session PANA session of the message to check.
  * 
  * @return 0 If the message is incorrect. 
  * @return 1 If the message is correct.
  * */
int checkPanaMessage(pana *msg, pana_ctx *pana_session);

/** 
 * Generates a Session ID from an IP and port given.
 * 
 * @param ip IP to use in the generation.
 * @param port Port to use in the generation.
 * 
 * @return Session Id generated.
 * */
int generateSessionId (char * ip, short port);

/** 
 * Returns the name of the message type given its code.
 * 
 * @param msg_type Message type code.
 * 
 * @return Message name. 
 * */
char * getMsgName(int msg_type);

/** 
 * Returns the name of the AVP given its code.
 * 
 * @param avp_code AVP code.
 * 
 * @return AVP name. 
 * */
char * getAvpName(int avp_code);

/**
 * Gets the NONCE AVP from a message. It makes a copy so the message
 * can be freed later.
 * 
 * @param message PANA Message to extract Nonce from.
 * 
 * @return Nonce AVP in u8 format.
 * */
u8 * extractNonce(char * message);

//FIXME: Poner que debe liberarse la memoria.
/** 
 * Generates the AUTH key given a PANA session.
 * The PANA_AUTH_KEY is derived from the available MSK, and it is used
 * to integrity protect PANA messages. The PANA_AUTH_KEY is computed in
 * the following way:
 * PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
 * 
 * See RFC 5191 Section 5.3 for more information.
 * 
 * @param current_session PANA session.
 * 
 * @return AUTH key generated.
 * */
u8 * generateAUTH(pana_ctx * current_session);

/**
 * Returns if an AVP is OctetString or not.
 * 
 * @param type AVP code.
 * 
 * @return If the AVP is OctetString.
 * */
int isOctetString(int type);

/**
 * Adds 1 to a character array given it's length.
 * @param value Array to increase.
 * @param length Array length.
 * */
void increase_one (char *value, int length);

//FIXME: Función que devuelve si las dos sesiones pana son iguales
int isEqual(pana_ctx* sess1, pana_ctx* sess2);

/**
 * Generates a Random Key Id and stores it in the parameter.
 * 
 * @param **global_key_id Where to store the random generated value
 * */
 int generateRandomKeyID (char** global_key_id);

/**
 * Returns the padding space needed given an OctetString size.
 * 
 * @param size AVP size.
 * 
 * @return Padding needed.
 */
int paddingOctetString(int size);

/** 
 * Returns the pointer to a given AVP in a message.
 * 
 * @param msg PANA message.
 * @param type AVP code to get.
 * 
 * @return Pointer to the AVP.
 * */
char * getAvp2(char *msg, int type);
char * getAvp(char *msg, int type);
/** Hashes the AUTH AVP given a key.
 * 
 * @param msg PANA message.
 * @param key Key to use during hashing.
 * @param key_len Key's length.
 * 
 * @return 0 The hash was successful.
 * @return 1 No AUTH AVP was found in the PANA message.
 * */
int hashAuth(char *msg, char* key, int key_len);

//Debugging functions
/** Debug function, shows in a friendly way the information contained in
 * a PANA message (includes AVPs in the value area).
 * @param *hdr panaMessage to be shown. */
void debug_pana(pana *hdr);

/** Debug function, shows in a friendly way the information contained in
 * an AVP.
 * @param *datos AVP to be shown. */
void debug_avp(avp_pana * datos);
#endif
