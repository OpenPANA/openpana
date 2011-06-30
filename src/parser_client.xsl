<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method = "text" />
<xsl:template match='/'>/*
 *  configclient.h
 *  
 * 	Configurable values to set client's options.
 *
 *  Copyright (C) Pedro Moreno Sánchez and Francisco Vidal Meca on 18/03/11.
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
 *  along with this program.  If not, see "http://www.gnu.org/licenses/"
 *  
 *  
 *  https://sourceforge.net/projects/openpana/
 */

#ifndef CONFIGCLIENT_H
#define CONFIGCLIENT_H


#define SRCPORT <xsl:value-of select="CONFIG/PAC/PORT"/>
#define DSTPORT	<xsl:value-of select="CONFIG/PAA/PORT"/> //PANAPORT
/** PaC's IP */
#define LOCALIP "<xsl:value-of select="CONFIG/PAC/IP"/>" // source ip
/** PAA's IP */
#define DESTIP "<xsl:value-of select="CONFIG/PAA/IP"/>"  // destination ip

/* A duration that is associated with a PANA session. For an
established PANA session, the session lifetime is bound to the
lifetime of the current authorization given to the PaC. The
session lifetime can be extended by a new round of EAP
authentication before it expires. Until a PANA session is
established, the lifetime SHOULD be set to a value that allows the
PaC to detect a failed session in a reasonable amount of time.
*/
/** Time necessary to do the authentication. */
#define FAILED_SESS_TIMEOUT_CONFIG <xsl:value-of select="CONFIG/PAC/SESSION/TIMEOUT"/> 

/** PRF ALGORITHM identifier*/
#define PRF_HMAC_SHA1	<xsl:value-of select="CONFIG/PAC/ALGORITHMS/PRF"/>
/** INTEGRITY ALGORITHM identifier*/
#define AUTH_HMAC_SHA1_160	<xsl:value-of select="CONFIG/PAC/ALGORITHMS/INTEGRITY"/>



#endif


</xsl:template>
</xsl:stylesheet>
