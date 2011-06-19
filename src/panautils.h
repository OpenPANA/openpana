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
 * Serializes (marshall) a panaMessage struct in a char * UDP PANA packet ready to be sended.
 * @param *msg PANA Message to be serialized.
 * @return The PANA Message serialized, it must be freed after used.
 */
char * serializePana(panaMessage *msg);

/**
 * Unserializes (unmarshall) a char * buffer containing an UDP PANA packet into
 * a panaMessage Struct.
 *
 * @param buf Buffer to be unserialized.
 * @param numbytes Size of the buffer in bytes.
 *
 * @return panaMessage
 */
panaMessage * unserializePana(char * buf, int numbytes);

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
int checkPanaMessage(panaMessage *msg, pana_ctx *pana_session);

/** Encrypts the AUTH AVP given a key.
 * 
 * @param msg PANA message.
 * @param key Key to use during encryption.
 * @param key_len Key's length.
 * 
 * @return 0 The encryption was successful.
 * @return 1 No AUTH AVP was found in the PANA message.
 * */
int cryptAuth(panaMessage *msg, char* key, int key_len);

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
 * Gets the NONCE AVP from a message.
 * @param message Message to extract Nonce from.
 * 
 * @return Nonce AVP in u8 format.
 * */
u8 * extractNonce(char * message);

//FIXME: Poner que debe liberarse la memoria.
/** 
 * Generates the AUTH key given a PANA session.
 * 
 * @param current_session PANA session.
 * 
 * @return AUTH key generated.
 * */
u8 * generateAUTH(pana_ctx * current_session);

/** 
 * Returns the pointer to a given AVP in a message.
 * 
 * @param msg PANA message.
 * @param type AVP code to get.
 * 
 * @return Pointer to the AVP.
 * */
avp * getAvp(panaMessage *msg, int type);

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

//Debugging functions
/** Debug function, shows in a friendly way the information contained in
 * an AVP struct.
 * @param *elmnt AVP to be shown. */
void debug_print_avp(avp *elmnt);

/** Debug function, shows in a friendly way the information contained in
 * a PANA message struct (includes AVPs in the value area).
 * @param *msg panaMessage to be shown. */
void debug_print_message(panaMessage *msg);

#endif
