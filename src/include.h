/**
 * @mainpage OpenPANA Documentation
 * @brief OpenPANA is a free implementation of the PANA protocol
 * (RFC 5191). It's a multithreading implementation, supported by a
 * framework, which allows multiple users to authenticate.
 * 
 * @author Pedro Moreno Sánchez & Francisco Vidal Meca
 * \n\n\n
 * Further information such as configuration, installation contact info
 * or acknowledgments can be found on the README file.
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
#ifdef HAVE_MATH_H
#include <math.h>
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

#define SET		1 /**< SET state. */
#define UNSET 	0 /**< UNSET state.*/
#define ERROR	-666 /**< ERROR state.*/

// External files' documentation
/** 
 * @file prf_plus.c
 * @brief Implements PRF functions to be used with OpenPANA.
 * @author Fernando Bernal Hidalgo
 */
 
 /** 
 * @file prf_plus.h
 * @brief Headers of PRF functions to be used with OpenPANA.
 * @author Fernando Bernal Hidalgo
 */
 
 /** 
 * @file eap_auth_interface.c
 * @brief EAP Authenticator's interface implementation.
 * @author Rafa Marín López
 */
 
 /** 
 * @file eap_auth_interface.h
 * @brief EAP Authenticator's interface headers.
 * @author Rafa Marín López
 */
 
 /** 
 * @file eap_peer_interface.c
 * @brief EAP Peer's interface implementation.
 * @author Rafa Marín López
 */
 
 /** 
 * @file eap_peer_interface.h
 * @brief EAP Peer's interface headers.
 * @author Rafa Marín López
 */
#endif