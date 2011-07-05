/*
 *  configclient.h
 *  
 * 	Configurable values to set client's options.
 *
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 18/03/11.
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

#ifndef CONFIGCLIENT_H
#define CONFIGCLIENT_H


#define SRCPORT 5360
#define DSTPORT	716 //PANAPORT
/** PaC's IP */
#define LOCALIP "127.0.0.1" // source ip
/** PAA's IP */
#define DESTIP "127.0.0.1"  // destination ip

/* A duration that is associated with a PANA session. For an
established PANA session, the session lifetime is bound to the
lifetime of the current authorization given to the PaC. The
session lifetime can be extended by a new round of EAP
authentication before it expires. Until a PANA session is
established, the lifetime SHOULD be set to a value that allows the
PaC to detect a failed session in a reasonable amount of time.
*/
/** Time necessary to do the authentication. */
#define FAILED_SESS_TIMEOUT_CONFIG 150 

#endif
