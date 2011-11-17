/**
 * @file panautils.h
 * @brief  Headers of functions wich performs various helpful actions
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
 *  https://sourceforge.net/projects/openpana/
 */

#ifndef PANAUTILS_H
#define PANAUTILS_H

#include "include.h"

#include "panamessages.h"
#include "./state_machines/session.h"

/** UDP port used for PANA.*/
#define PANAPORT 716
/** Maximum size to use with an UDP packet. */
#define MAXSIZEUDP 1280

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
uint32_t generateSessionId (char * ip, uint16_t port);

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
 * @return AUTH key generated. It must to be freed when no longer needed.
 * */
u8 * generateAUTH(pana_ctx * current_session);

/**
 * Adds 1 to a character array given it's length.
 * @param value Array to increase.
 * @param length Array length.
 * */
void increase_one (char *value, int length);

/**
 * Generates a Random Key Id and stores it in the parameter.
 * 
 * @param **global_key_id Where to store the random generated value
 * */
 int generateRandomKeyID (char** global_key_id);

/** 
 * Hashes the AUTH AVP given a key.
 * 
 * @param msg PANA message.
 * @param key Key to use during hashing.
 * @param key_len Key's length.
 * 
 * @return 0 The hash was successful.
 * @return 1 No AUTH AVP was found in the PANA message.
 * */
int hashAuth(char *msg, char* key, int key_len);

/**
 * Given a string cointaining an hexadecimal number and its length, 
 * returns its value in an integer variable.
 * 
 * @param *value Hexadecimal number.
 * @param length Array length.
 * 
 * @return Integer value of the hexadecimal array.
 * */
int Hex2Dec (char * value, int length) ;

/**
 * Sends the message. IPv4 support
 * 
 * @param destaddr Information needed to send the message.
 * @param *msg Message to send.
 * @param sock Socket to use during sending.
 * 
 * @return -1 In case of error.
 * @return Number of bytes sended.
 * */
int sendPana(struct sockaddr_in destaddr, char *msg, int sock);

/**
 * Sends the message. IPv6 support
 * 
 * @param destaddr6 Information needed to send the message.
 * @param *msg Message to send.
 * @param sock Socket to use during sending.
 * 
 * @return -1 In case of error.
 * @return Number of bytes sended.
 * */
int sendPana6(struct sockaddr_in6 destaddr6, char *msg, int sock);
/**
 * Returns the actual time of the system.
 * 
 * @return Time of the system.
 * */
double getTime();

/** 
 * Suspends execution for microseconds intervals.
 * @param wait Microseconds.
 * */
void waitusec(unsigned int wait);
/** 
 * Suspends execution for nanoseconds intervals.
 * @param wait Nanoseconds.
 * */
void waitnano(long wait);
/**
 * Prints a warning message. Its used the same exact way printf() would.
 * @param *message warning message.
 * */
void pana_warning (const char *message, ...);
/**
 * Prints an error message. Its used the same exact way printf() would.
 * @param *message error message.
 * */
void pana_error (const char *message, ...);
/**
 * Prints a fatal error message and exits with a failure status. 
 * Its used the same exact way printf() would.
 * @param *message fatal error message.
 * */
void pana_fatal (const char *message, ...);
/**
 * Prints a debug message, it'll only print in debug mode.
 * Its used the same exact way printf() would.
 * @param *message debug message.
 * */
void pana_debug (const char *message, ...);
#endif
