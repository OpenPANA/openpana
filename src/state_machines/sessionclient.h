/**
 * @file sessionclient.h
 * @brief PaC's session attributes.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2010.
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
 
#ifndef SESSIONCLIENT_H
#define SESSIONCLIENT_H

/**
 * PANA context only for PaCs.
 * */
typedef struct {
    // Configurable value
    /**
     * This is a configurable value that allows the PaC to determine
     * whether a PaC authentication and authorization phase has stalled
     * without an explicit EAP success or failure notification.
     */
    int FAILED_SESS_TIMEOUT;

    // Variables
    /**
     * This event variable is set to TRUE when initiation of EAP-based
     * (re-)authentication is triggered by the application.
     */
    bool AUTH_USER;
    
} pana_client_ctx;
#endif
