/*
 *  panamessages.h
 *
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

#ifndef PANAMESSAGE
#define PANAMESSAGE
#include <arpa/inet.h>
int asprintf(char **strp, const char *fmt, ...); //FIXME: como solucionar esto?
#define _GNU_SOURCE //To avoid implicit declaration warning on asprintf

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
/**PANA-Auth-Request message type. */
#define PAR_MSG 2
/**PANA-Auth-Answer message type. */
#define PAN_MSG 2
/**PANA-Termination-Request message type. */
#define PTR_MSG 3
/**PANA-Termination-Answer message type. */
#define PTA_MSG 3
/**PANA-Notification-Request message type. */
#define PNR_MSG 4
/**PANA-Notification-Answer message type. */
#define PNA_MSG 4

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

//Cada flag representa un AVP, la entrada de string del tx se
//transformará a éste formato por ser mucho más rápido para tratarlo.
#define F_AUTH 0x0001
#define F_EAPP 0x0002
#define F_INTEG 0x0004
#define F_KEYID 0x0008
#define F_NONCE 0x0010
#define F_PRF 0x0020
#define F_RES 0x0040
#define F_SESS 0x0080
#define F_TERM 0x0100

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
    short reserved;
    /** The Message Length field is two octets and indicates the length
     *  of the PANA message including the header fields.*/
    short msg_length;

    /** The Flags field is two octets. The following bits are assigned:
     * \code
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |R S C A P I r r r r r r r r r r|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ \endcode
     * The flags marked as 'r' are reserved for future use. They MUST be
     * set to zero and ignored by the receiver. */
    short flags;
    /** The Message Type field is two octets, and it is used in order to
     * communicate the message type with the message. Message Type
     * allocation is managed by IANA. */
    short msg_type;
    /** This field contains a 32-bit session identifier. */
    int session_id;
    /** This field contains a 32-bit sequence number. */
    int seq_number;
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
    unsigned short code;
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
    unsigned short flags;
    /**
     * The AVP Length field is two octets, and indicates the number of
     * octets in the Value field. The length of the AVP Code, AVP
     * Length, AVP Flags, Reserved and Vendor-Id fields are not counted
     * in the AVP Length value.
     */
    unsigned short length;
    /**
     * This two-octet field is reserved for future use.
     * It MUST be set to zero and ignored by the receiver.
     * */
    unsigned short reserved;
} __attribute__((packed)) avp_pana;

/**
 * A procedure to send a PANA message to its peering PANA entity. \n\n 
 * See RFC 5609 as void Tx:PANA_MESSAGE_NAME[flag](AVPs)
 * 
 * @param *msgtype Name's abbreviation of the packet to be sent e.g. 
 * "PAR". 
 * @param flags Contains one or more flags to be set to the message, 
 * except for ’R’ (Request) flag.
 * @param sequence_number Sequence number field of the message.
 * @param sess_id Session id field of the message.
 * @param *avps Contains a list of names of optional AVPs to be
 * inserted in the message, except for AUTH AVP.
 * @param destaddr Socket information to use during transmission.
 * @param data Data to be used in the AVP generation.
 * @param sock Socket to use in the transmission.
 * 
 * @return Message sended. It must to be freed when no longer needed.
 */
char * transmissionMessage(char * msgtype, short flags, int *sequence_number, int sess_id, char * avps, struct sockaddr_in destaddr, void **data, int sock);

/**
 * A procedure to insert AVPs for each specified AVP name in the list
 * of AVP names in the PANA message. When an AVP name ends with "*",
 * zero, one, or more AVPs are inserted; otherwise, one AVP is
 * inserted. \n\n See RFC 5609 as 
 * void PANA_MESSAGE_NAME.insertAvp("AVP_NAME1","AVP_NAME2",...).
 * 
 * @param *msg PANA message to insert the AVPs.
 * 
 * @param *names AVP names to be inserted in the message.
 * 
 * @param **data AVP data to use during their generation.
 */
//void insertAvp(panaMessage* msg, char * names, void **data);
int AVPgenerateflags(char * avps);
int AVPname2flag(char * avp_name);
/**
 * A procedure that checks whether an AVP of the specified AVP name
 * exists in the specified PANA message \n\n See RFC 5609 as
 *  void PANA_MESSAGE_NAME.existAvp("AVP_NAME")
 * 
 * @param *message Message to be checked.
 * 
 * @param *avp_name AVP name to be checked.
 * 
 * @return 1 (TRUE) if the specified AVP is found.
 * 
 * @return 0 (FALSE) if the specified AVP isn't found.
 */
int existAvp(char * message, char *avp_name);

/**
 * A procedure that generates the struct that matches the name of the avp
 * given and inserts it in a AVP list.
 * 
 * @param *lista List of AVPs to insert the AVP given.
 * 
 * @param *avp_name Name of the AVP to be generated and inserted.
 */

int insertAvps(char** message, int avps, void **data);

#endif
