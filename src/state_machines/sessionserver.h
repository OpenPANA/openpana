/**
 * @file sessionserver.h
 * @brief PAA's session attributes.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2011.
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
#ifndef SESSIONSERVER_H
#define SESSIONSERVER_H

/**
 * PANA context only for PAAs.
 * */
typedef struct {
    // Variables
    /**
     * This variable indicates whether the PAA is able to piggyback an
     * EAP-Request in the initial PANA-Auth-Request. Otherwise, it is
     * set to FALSE.
     */
    int OPTIMIZED_INIT;

    /**
     * This variable is set to TRUE as a result of a PAA-initiated
     * handshake.
     */
    int PAC_FOUND;

    /**
     * This event variable is set to TRUE to indicate that the PAA
     * initiates a re-authentication with the PaC. The re-authentication
     * timeout should be set to a value less than the session timeout
     * carried in the Session-Lifetime AVP if present.
     */
    int REAUTH_TIMEOUT;

    /**
     *	This variable is set whith the key identifier value when a new MSK
     *  is available.
     */ 
    char * global_key_id;
    
    int RTX_COUNTER_AAA;/**< Number of retransmission to AAA*/
} pana_server_ctx;

#endif
