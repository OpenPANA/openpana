/**
 * @mainpage OpenPANA Documentation
 * @brief \image html med_logo.png 
 *  OpenPANA is a free implementation of the PANA protocol
 * (RFC 5191). It's a multithreading implementation, supported by a
 * framework, which allows multiple users to authenticate.
 * \n\n\n
 * Further information such as configuration, installation contact info
 * or acknowledgments can be found on the README file.
 * 
 * @author Pedro Moreno Sánchez <p.morenosanchez@um.es>
 * @author Francisco Vidal Meca <f.vidalmeca@um.es>
 * 
 * \image latex big_logo.eps "OpenPANA logo" width=\textwidth/5
 *  
 * @file include.h
 * @brief This header file is included into all C files so that commonly
 * used header files can be selected with specific ifdef blocks in one
 * place instead of having to have specific selection in many files.
 */
 
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 16/08/11.
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

#ifndef INCLUDE_H
#define INCLUDE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_SEMAPHORE_H
#include <semaphore.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h> 
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
	#define true 1
	#define false 0
	typedef int bool
#endif

#define TRUE true
#define FALSE false

#include <stdarg.h>
#include <stdio.h>      
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>

//Cryptographic suites implemented
#define PRF_HMAC_SHA1 2
#define PRF_AES128_CBC 5
#define AUTH_HMAC_SHA1_160 7
#define AUTH_AES_CMAC 8

#ifndef EXIT_SUCCESS
	#define EXIT_SUCCESS  0
	#define EXIT_FAILURE  1
#endif

#ifndef KEY_ID_LENGTH
	#define KEY_ID_LENGTH  4
#endif

#ifndef INTEG_AVP_VALUE_LENGTH
	#define INTEG_AVP_VALUE_LENGTH  4
#endif

#ifndef NONCE_AVP_VALUE_LENGTH
#define NONCE_AES_AVP_VALUE_LENGTH  8
#define NONCE_HMAC_AVP_VALUE_LENGTH  20
#endif

#ifndef PRF_AVP_VALUE_LENGTH
	#define PRF_AVP_VALUE_LENGTH  4
#endif

#ifndef RESCODE_AVP_VALUE_LENGTH
	#define RESCODE_AVP_VALUE_LENGTH  4
#endif

#ifndef SESSLIFETIME_AVP_VALUE_LENGTH
	#define SESSLIFETIME_AVP_VALUE_LENGTH  4
#endif

#ifndef TERMCAUSE_AVP_VALUE_LENGTH
	#define TERMCAUSE_AVP_VALUE_LENGTH  4
#endif

#ifndef AUTH_AVP_VALUE_LENGTH
#define AUTH_AES_AVP_VALUE_LENGTH  16	
#define AUTH_HMAC_AVP_VALUE_LENGTH  20
#endif

#ifndef MSK_LENGTH
	#define MSK_LENGTH  64
#endif

#ifndef AUTH_KEY_LENGTH
	#define AUTH_KEY_LENGTH  20
#endif

#define SET		1 /**< SET state. */
#define UNSET 	0 /**< UNSET state.*/
#define ERROR	-666 /**< ERROR state.*/

// Memory managment wrappers' headers, they'll be implemented on
// panautils.c, but they'll need to be included every file 
/** Macro to use xcalloc */
#define XCALLOC(type, num)                                  \
        ((type *) xcalloc ((num), sizeof(type)))
/** Macro to use xmalloc */
#define XMALLOC(type, num)                                  \
        ((type *) xmalloc ((num) * sizeof(type)))
/** Macro to use xrealloc */
#define XREALLOC(type, p, num)                              \
        ((type *) xrealloc ((p), (num) * sizeof(type)))
/** Macro to use free */
#define XFREE(stale)                            do {        \
        if (stale) { free (stale);  stale = 0; }            \
                                                } while (0)
/** calloc wrapper to handle 'out of memory' problems*/
extern void *xcalloc    (size_t num, size_t size);
/** malloc wrapper to handle 'out of memory' problems*/
extern void *xmalloc    (size_t num);
/** realloc wrapper to handle 'out of memory' problems*/
extern void *xrealloc   (void *p, size_t num);

// External files' documentation, in order to create doxygen
// documentation without modifying them
/** 
 * @file prf_plus.c
 * @brief Implements PRF functions to be used with OpenPANA.
 * @author Fernando Bernal Hidalgo
 * 
 * @file prf_plus.h
 * @brief Headers of PRF functions to be used with OpenPANA.
 * @author Fernando Bernal Hidalgo
 * 
 * @file eap_auth_interface.c
 * @brief EAP Authenticator's interface implementation.
 * @author Rafa Marín López
 * 
 * @file eap_auth_interface.h
 * @brief EAP Authenticator's interface headers.
 * @author Rafa Marín López
 * 
 * @file eap_peer_interface.c
 * @brief EAP Peer's interface implementation.
 * @author Rafa Marín López
 * 
 * @file eap_peer_interface.h
 * @brief EAP Peer's interface headers.
 * @author Rafa Marín López
 */
 
 /**
  * \page license License
  * Basically this software suites follows the GNU GPL v3 license.
  * In short, the code is freely available but with no warranty.
  * 
  * Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2010.
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
  *  \image html favicon.ico
  *  \image html tiny_logo.png
  * 
  *  https://sourceforge.net/projects/openpana/
  * 
  * */
#endif
