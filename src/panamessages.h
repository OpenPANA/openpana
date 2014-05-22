/**
 * @file panamessages.h
 * @brief  Headers of functions to work with PANA messages.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 07/09/10.
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

#ifndef PANAMESSAGE_H
#define PANAMESSAGE_H
#include "include.h"

//Flag definition: See RFC 5191 6.2
/** PANA message flag definition. If set, the message is a request.
 * If cleared, the message is an answer. */
#define R_FLAG 0x8000

/** PANA message flag definition. If set, the message is the first
 * PANA-Auth-Request or PANA-Auth-Answer in authentication and
 * authorization phase. For other messages, this bit MUST be cleared.*/
#define S_FLAG 0x4000

/** PANA message flag definition. If set, the message is the last
 * PANA-Auth-Request or PANA-Auth-Answer in authentication and
 * authorization phase. For other messages, this bit MUST be cleared.*/
#define C_FLAG 0x2000

/** PANA message flag definition. If set, the message is a
 * PANA-Notification-Request or PANA-Notification-Answer to initiate
 * re-authentication. For other messages, this bit MUST be cleared. */
#define A_FLAG 0x1000

/** PANA message flag definition. If set, the message is a
 * PANA-Notification-Request or PANA-Notification-Answer for liveness 
 * test. For other messages, this bit MUST be cleared. */
#define P_FLAG 0x0800

/** PANA message flag definition. If set, it indicates that the PaC is
 * required to perform IP address reconfiguration after successful 
 * authentication and authorization phase to configure an IP address 
 * that is usable for exchanging data traffic across EP. This bit is set
 * by the PAA only for PANA-Auth-Request messages in the authentication 
 * and authorization phase. For other messages, this bit MUST be cleared.
 */
#define I_FLAG 0x0400

//PANA messages types definition, see RFC section 7
/**PANA-Client-Initiation message type. */
#define PCI_MSG 1
/**PANA-Auth message type. */
#define PAUTH_MSG 2
/**PANA-Termination message type. */
#define PTERM_MSG 3
/**PANA-Notification message type. */
#define PNOTIF_MSG 4
/**PANA-Relay message type .*/
#define PRY_MSG 5

//AVP Codes definition, see RFC 5191 section 8
/** AUTH AVP code */
#define AUTH_AVP 1
/** EAP-Payload AVP code */
#define EAPPAYLOAD_AVP 2
/** Integrity-Algorithm AVP code */
#define INTEGRITYALG_AVP 3
/** Key-Id AVP code */
#define KEYID_AVP 4
/** Nonce AVP code */
#define NONCE_AVP 5
/** PRF-Algorithm AVP code */
#define PRFALG_AVP 6
/** Result-Code AVP code */
#define RESULTCODE_AVP 7
/** Session-Lifetime AVP code */
#define SESSIONLIFETIME_AVP 8
/** Termination-Cause AVP code */
#define TERMINATIONCAUSE_AVP 9
/** PaC-Information AVP code */
#define PACINFORMATION_AVP 10
/** Relayed-Message AVP code */
#define RELAYEDMESSAGE_AVP 11

//Cada flag representa un AVP, la entrada de string del tx se
//transformará a éste formato por ser mucho más rápido para tratarlo.
/** AVP flag definition for internal use. Represents the Auth AVP.*/
#define F_AUTH 0x0001
/** AVP flag definition for internal use. Represents the Eap-Payload AVP.*/
#define F_EAPP 0x0002
/** AVP flag definition for internal use. Represents the Integrity-Algorithm
 *  AVP.*/
#define F_INTEG 0x0004
/** AVP flag definition for internal use. Represents the Key-Id AVP.*/
#define F_KEYID 0x0008
/** AVP flag definition for internal use. Represents the Nonce AVP.*/
#define F_NONCE 0x0010
/** AVP flag definition for internal use. Represents the PRF-Algorithm
 *  AVP.*/
#define F_PRF 0x0020
/** AVP flag definition for internal use. Represents the Result-Code
 *  AVP.*/
#define F_RES 0x0040
/** AVP flag definition for internal use. Represents the Session-Lifetime
 *  AVP.*/
#define F_SESS 0x0080
/** AVP flag definition for internal use. Represents the Termination-Cause
 *  AVP.*/
#define F_TERM 0x0100
/** AVP flag definition for internal use. Represents the PaC-Information
 *  AVP.*/
#define F_PACINF 0x0200
/** AVP flag definition for internal use. Represents the Relayed-Message
 *  AVP.*/
#define F_RLYMSG 0x0400

/**
 * PANA message is made from a header and a group of AVPs included 
 * in the message.
 * 
 * A summary of the PANA message header format is shown below. The 
 * fields are transmitted in network byte order. \code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reserved            |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Flags             |            Message Type       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Session Identifier                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Sequence Number                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | AVPs ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+- \endcode
 * 
 * See paragraph 6.2. PANA Message Header in RFC 5191
 */
typedef struct {
    /** This 16-bit field is reserved for future use. It MUST be set to
     * zero and ignored by the receiver. */
    uint16_t reserved;
    /** The Message Length field is two octets and indicates the length
     *  of the PANA message including the header fields.*/
    uint16_t msg_length;

    /** The Flags field is two octets. The following bits are assigned:
     * \code
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |R S C A P I r r r r r r r r r r|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ \endcode
     * The flags marked as 'r' are reserved for future use. They MUST be
     * set to zero and ignored by the receiver. */
    uint16_t flags;
    /** The Message Type field is two octets, and it is used in order to
     * communicate the message type with the message. Message Type
     * allocation is managed by IANA. */
    uint16_t msg_type;
    /** This field contains a 32-bit session identifier. */
    uint32_t session_id;
    /** This field contains a 32-bit sequence number. */
    uint32_t seq_number;
} __attribute__((packed)) pana;

/**
 * AVPs are a method of encapsulating information relevant to the
 * PANA message. The fields in the AVP are sent in network byte order.\n
 * 
 * AVP Format: \code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           AVP Code            |           AVP Flags           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          AVP Length           |            Reserved           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Vendor-Id (opt)                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Value ...
 * +-+-+-+-+-+-+-+-+ \endcode
 * 
 * See paragraph 6.3 in RFC 5191 for more information on AVPs.
 */
typedef struct {
    /**
     * The AVP Code, together with the optional Vendor-Id field,
     * identifies an attribute that follows. If the V-bit is not set,
     * then the Vendor-Id is not present and the AVP Code refers to an
     * IETF attribute.
     */
    uint16_t code;
    /**
     * The AVP Flags field is two octets. The following bits are
     * assigned: \code
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |R S C A P I r r r r r r r r r r|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ \endcode
     *
     * The ’V’ (Vendor) bit indicates whether the optional Vendor-Id
     * field is present in the AVP header. When set, the AVP Code
     * belongs to the specific vendor code address space. All AVPs
     * defined in this document MUST have the ’V’ (Vendor) bit cleared.\n
     *
     * r (reserved): These flag bits are reserved for future use.
     * They MUST be set to zero and ignored by the receiver.
     */
    uint16_t flags;
    /**
     * The AVP Length field is two octets, and indicates the number of
     * octets in the Value field. The length of the AVP Code, AVP
     * Length, AVP Flags, Reserved and Vendor-Id fields are not counted
     * in the AVP Length value.
     */
    uint16_t length;
    /**
     * This two-octet field is reserved for future use.
     * It MUST be set to zero and ignored by the receiver.
     * */
    uint16_t reserved;
} __attribute__((packed)) avp_pana;

/**
 * A procedure to send a PANA message to its peering PANA entity. 
 * See RFC 5609 as void Tx:PANA_MESSAGE_NAME[flag](AVPs)
 * 
 * @param *msgtype Name's abbreviation of the packet to be sent e.g. 
 * "PAR". 
 * @param flags Contains none, one or more flags to be set to the message, 
 * except for ’R’ (Request) flag.
 * @param *sequence_number Pointer to the sequence number field of the message.
 * @param sess_id Session id field of the message.
 * @param *avps Contains a list of optional AVPs to be
 * inserted in the message, except for AUTH AVP. AVPs will be passed as
 * a combination of AVP flags described in this file.
 * @param ip_ver Version IP identifier.
 * @param destaddr Socket information to use during transmission. It should be
 * a struct of type struct sockaddr_in if IPv4 is used or a struct of type
 * sockaddr_in6 if IPv6 is used.
 * @param data *data to be used in the AVP insertion.
 * @param sock Socket to use in the transmission.
 * @param msg_relayed Flag to indicate if a message needs to be relayed. If the message
 * is relayed (value = TRUE), the message is not really sent. The transmissionRelayedMessage must be called.
 * 
 * @return Message sended. It must to be freed when no longer needed.
 */
char * transmissionMessage(char * msgtype, uint16_t flags, uint32_t *sequence_number, uint32_t sess_id, uint16_t avps, int ip_ver, void * destaddr, void **data, int sock, uint8_t msg_relayed);

/** A procedure to send a PANA Relay message to its peering entity
 * @param ip_ver IP addresing version used.
 * @param destaddr Socket information to use during transmission. It should be
 * a struct of type struct sockaddr_in if IPv4 is used or a struct of type
 * sockaddr_in6 if IPv6 is used.
 * @param msg PANA message to be relayed.
 * @param sock Socket to use in the transmission.
 *
 * @return Message sended. It must to be freed when no longer needed.
 * */
char * transmissionRelayedMessage (int ip_ver, void *destaddr, char* msg, int sock, void *pacaddr);

/**
 * A procedure that checks whether an AVP of the specified AVP name
 * exists in the specified PANA message \n\n See RFC 5609 as
 *  void PANA_MESSAGE_NAME.existAvp("AVP_NAME")
 * 
 * @param *message Message to be checked.
 * 
 * @param *avp AVP to be checked. Using it's flag.
 * 
 * @return 1 (TRUE) if the specified AVP is found.
 * 
 * @return 0 (FALSE) if the specified AVP isn't found.
 */
bool existAvp(char * message, uint16_t avp);

/**
 * A procedure that inserts the given AVPs with their data into a PANA 
 * message.
 * 
 * @param **message Message to insert the AVPs to.
 * @param avps Flags of the AVPs to insert. 
 * @param **data AVP data to use during insertion.
 * @param ip_version IP addressing version used.
 * 
 * @return 0 (FALSE) if an error ocurred.
 * @return Total size of the AVP Payload.
 * @see AVPgenerateflags To details on AVP flags
 */

uint16_t insertAvps(char** message, int avps, void **data);

/** 
 * Returns the pointer to a given AVP in a message.
 * 
 * @param msg PANA message.
 * @param type AVP code to get.
 * 
 * @return Pointer to the AVP.
 * */
char * getAvp(char *msg, uint16_t type);

/** 
 * Returns the name of the message type given its code.
 * 
 * @param msg_type Message type code.
 * 
 * @return Message name. 
 * */
char * getMsgName(uint16_t msg_type);

//Debugging functions
/** Debug function, shows in a friendly way the information contained in
 * a PANA message (includes AVPs in the value area).
 * @param *hdr panaMessage to be shown. */
void debug_msg(pana *hdr);

/** Debug function, shows in a friendly way the information contained in
 * an AVP.
 * @param *datos AVP to be shown. */
void debug_avp(avp_pana * datos);
#endif
