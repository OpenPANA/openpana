/*
 *  eap_auth_interface.h
 *  
 *
 *  Created by Rafa Marin Lopez on 04/05/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 */

#ifndef EAP_AUTH_INTERFACE_H
#define EAP_AUTH_INTERFACE_H

#include "includes.h"
#include "common.h"
#include "crypto/tls.h"
#include "eap_server/eap.h"
#include "wpabuf.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "rsn_supp/wpa.h"
#include "eloop.h"
#include "../wpa_supplicant/wpa_supplicant_i.h"
#include "../wpa_supplicant/config.h"
#include <pthread.h>

/*struct recv_msg {
	struct sockaddr_in dst_addr; 
	struct wpabuf *msg;
	int addr_size;
	int sock;
};*/


struct extra_radius_attr {
	u8 type;
	char syntax;
	char *data;
	struct extra_radius_attr *next;
};

struct eap_auth_ctx;

struct radius_ctx {
	struct radius_client_data *radius;
	struct hostapd_radius_servers conf;
	//u8 radius_identifier;
	struct in_addr own_ip_addr; //OK
	//u8 *eap_identity;
	//size_t eap_identity_len;
	struct extra_radius_attr *extra_attrs;
	u8 own_addr[6];//mac addrs
    u8 *connect_info;
	//struct radius_msg *last_recv_radius;
		//int radius_access_accept_received;
	//int radius_access_reject_received;
	
    struct eap_auth_ctx *eap_ctx; /*It is a linked list*/
	/*u8 authenticator_msk[64];
	size_t authenticator_msk_len;*/
	/*int auth_serv_sock, auth_serv_sock6;
	 int auth_serv_sock, acct_serv_sock6;*/
};

/*struct eap_ll_callbacks {
	void (*disconnect)(void *ctx, u16 reason);
	void (*eap_auth_failure_report)(void *ctx);
	void (*authz_failure_report)(void *ctx);
	int  (*eap_ll_st_step)(void *ctx);
};*/



struct eap_auth_ctx {
	struct eap_eapol_interface *eap_if; /*Interface lower-layer <-> EAP state machine following RFC 4137*/
	struct eap_sm *eap;/*EAP full authenticator state machine*/
	struct radius_ctx *rad_ctx;
	u8 radius_identifier;
	struct radius_msg *last_recv_radius;
	struct radius_msg *last_send_radius;
	int radius_access_reject_received;
	//u8 *last_eap_radius; /* last received EAP Response from Authentication
						  //* Server */
	//size_t last_eap_radius_len;
	int radius_num_reauths; /*Not used so far*/
	u8 own_addr[6];//PaC's MAC addr.
	u8 *eap_identity;
	size_t eap_identity_len;
	/*u8 authenticator_msk[64];
	size_t authenticator_msk_len;*/
	void *tls_ctx;
	struct eap_auth_ctx *next;
	struct eap_method *eap_methods;
	struct wpabuf *eapRequest;
	void *eap_ll_ctx;
	//struct eap_ll_callbacks *eap_ll_cb;
};

/*int eap_auth_init(struct eap_auth_ctx *eap_ctx, 
				  struct radius_ctx *rad_ctx,
				  struct eapol_callbacks *eap_cb, struct eap_config *eap_conf);*/

int eap_auth_init(struct eap_auth_ctx *eap_ctx, void *eap_ll_ctx);
void eap_auth_deinit(struct eap_auth_ctx *eap_ctx);
//void eap_auth_rx(struct eap_auth_ctx *eap_ctx,const u8 *data, size_t data_len);
int eap_auth_step(struct eap_auth_ctx* eap_ctx);
/****************Interface EAP lower-layer and EAP stack***************/
void eap_auth_set_eapResp(struct eap_auth_ctx* eap_ctx, Boolean value);
void eap_auth_set_eapRespData(struct eap_auth_ctx* eap_ctx, const u8 *eap_packet, size_t eap_packet_len);
void eap_auth_set_portEnabled(struct eap_auth_ctx* eap_ctx, Boolean value);
void eap_auth_set_eapRestart(struct eap_auth_ctx* eap_ctx, Boolean value);
void eap_auth_set_eapTimeout(struct eap_auth_ctx* eap_ctx, Boolean value);
void eap_auth_set_retransWhile(struct eap_auth_ctx* eap_ctx, int retransWhile);
void eap_auth_set_eapSRTT(struct eap_auth_ctx* eap_ctx, int eapSRTT);
void eap_auth_set_eapRTTVAR(struct eap_auth_ctx* eap_ctx, int eapRTTVAR);
Boolean eap_auth_get_eapReq(struct eap_auth_ctx* eap_ctx);
void eap_auth_set_eapReq(struct eap_auth_ctx* eap_ctx, Boolean value);
struct wpabuf *eap_auth_get_eapReqData(struct eap_auth_ctx* eap_ctx);
Boolean eap_auth_get_eapNoReq(struct eap_auth_ctx* eap_ctx);
void eap_auth_set_eapNoReq(struct eap_auth_ctx* eap_ctx, Boolean value);
Boolean eap_auth_get_eapSuccess(struct eap_auth_ctx* eap_ctx);
void eap_auth_set_eapSuccess(struct eap_auth_ctx* eap_ctx, Boolean value);
Boolean eap_auth_get_eapFail(struct eap_auth_ctx* eap_ctx);
void eap_auth_set_eapFail(struct eap_auth_ctx* eap_ctx, Boolean value);
Boolean eap_auth_get_eapTimeout(struct eap_auth_ctx* eap_ctx);
Boolean eap_auth_get_eapKeyAvailable(struct eap_auth_ctx* eap_ctx);
u8 *eap_auth_get_eapKeyData(struct eap_auth_ctx* eap_ctx, size_t *key_len);
/************************************************************************/
u8 *eap_auth_get_eapIdentity(struct eap_auth_ctx *eap_ctx, size_t *length);
/************************************************************************/
struct radius_ctx *rad_client_init();
struct radius_client_data *get_rad_client_ctx();
int add_eap_ctx_rad_client(struct eap_auth_ctx *eap_ctx);
struct eap_auth_ctx *search_eap_ctx_rad_client(u8 identifier);

#endif
