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

/* 
 * Devuelve si un mensaje pana es correcto, comprueba que la cabecera
 * sea correcta (flags, reservado, tipos de mensaje), numeros de seq,
 * tipos de mensajes, session_id y valor del auth si existe.
 */
int checkPanaMessage(panaMessage *msg, pana_ctx *pana_session);

//FIXME: Es la función que encripta el auth avp con la clave
int cryptAuth(panaMessage *msg, char* key, int key_len);

//FIXME: Genera el Session ID a partir de la IP y el Puerto dado del cliente
int generateSessionId (char * ip, short port);

//FIXME: Devuelve el tipo del mensaje a partir de su código
char * getMsgName(int msg_type);

//FIXME: Devuelve el tipo de AVP a partir de su código
char * getAvpName(int avp_code);

//FIXME: Extrae el NONCE
u8 * extractNonce(char * message);

//FIXME: Genera la clave AUTH a partir de los datos de la sesion
//Poner que debe liberarse la memoria.
u8 * generateAUTH(pana_ctx * current_session);

//FIXME: Funcion que obtiene un puntero avp del tipo determinado de un mensaje
avp * getAvp(panaMessage *msg, int type);

//FIXME: Función que devuelve si un tipo de avp es octetString o no
int isOctetString(int type);

//FIXME: Función que genera el key id y lo guarda en el parámetro
int generateKeyID (char* key_id, int key_id_length, u8* msk_key, unsigned int msk_len);

//FIXME: Calcula el padding necesario para el avp de tipo octetstring
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
