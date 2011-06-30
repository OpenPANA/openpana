<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method = "text" />
<xsl:template match='/'>/*
 *  configserver.h
 *  
 * 	Configurable values to set server's options.
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
 
#ifndef CONFIGSERVER_H
#define CONFIGSERVER_H

#define SRCPORT <xsl:value-of select="CONFIG/PAA/PORT"/> //PANAPORT

/* A duration that is associated with a PANA session. For an
established PANA session, the session lifetime is bound to the
lifetime of the current authorization given to the PaC. The
session lifetime can be extended by a new round of EAP
authentication before it expires. Until a PANA session is
established, the lifetime SHOULD be set to a value that allows the
PaC to detect a failed session in a reasonable amount of time.
*/
/**Timeout for expiring a session in the server*/
#define LIFETIME_SESSION_TIMEOUT_CONFIG <xsl:value-of select="CONFIG/PAA/SESSION/TIMEOUT"/>
/**Timeout for expiring client session*/
#define LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG <xsl:value-of select="CONFIG/PAA/TIMEOUT_CLIENT"/>
/** Number of threads used to service requests */
#define NUM_WORKERS <xsl:value-of select="CONFIG/PAA/WORKERS"/>
/**Time while a session is on the server without answer*/
#define TIME_PCI <xsl:value-of select="CONFIG/PAA/TIME_ANSWER"/>			

/** PRF ALGORITHM identifier*/
#define PRF_HMAC_SHA1	<xsl:value-of select="CONFIG/PAA/ALGORITHMS/PRF"/>
/** INTEGRITY ALGORITHM identifier*/
#define AUTH_HMAC_SHA1_160	<xsl:value-of select="CONFIG/PAA/ALGORITHMS/INTEGRITY"/>

#endif


</xsl:template>
</xsl:stylesheet>
