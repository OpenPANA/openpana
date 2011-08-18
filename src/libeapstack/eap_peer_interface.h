/*
 *  eap_peer_interface.h
 *  
 *
 *  Created by Rafa Marin Lopez on 27/10/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 */
#ifndef EAP_PEER_INTERFACE_H
#define EAP_PEER_INTERFACE_H

#include "includes.h"

#include "common.h"
#include "eap_peer/eap.h"
#include "eap_peer/eap_config.h"
#include "wpabuf.h"

struct eap_peer_ctx {
	Boolean eapSuccess;
	Boolean eapRestart;
	Boolean eapFail;
	Boolean eapResp;
	Boolean eapNoResp;
	Boolean eapReq;
	Boolean portEnabled;
	Boolean altAccept; /* for EAP */
	Boolean altReject; /* for EAP */
	
	struct wpabuf *eapReqData; /* for EAP */
	
	unsigned int idleWhile; /* for EAP state machine */
	
	struct eap_peer_config eap_config;
	struct eap_sm *eap;
	struct eap_method *eap_methods;
	void *eap_ll_ctx;
};

int eap_peer_init(struct eap_peer_ctx *eap_ctx, void *eap_ll_ctx,char * user, char * passwd, char * cacert, char * ccert, char * ckey, char * pkey, int fsize);
int eap_peer_step(struct eap_peer_ctx *eap_ctx);
void eap_peer_set_eapReq(struct eap_peer_ctx* eap_ctx, Boolean value);
void eap_peer_set_eapReqData(struct eap_peer_ctx* eap_ctx, const u8 *eap_packet, size_t eap_packet_len);
void eap_peer_set_portEnabled(struct eap_peer_ctx* eap_ctx, Boolean value);
void eap_peer_set_idleWhile(struct eap_peer_ctx* eap_ctx, unsigned int idleWhile);
void eap_peer_set_eapRestart(struct eap_peer_ctx* eap_ctx, Boolean value);
Boolean eap_peer_get_altReject(struct eap_peer_ctx* eap_ctx);
Boolean eap_peer_get_altAccept(struct eap_peer_ctx* eap_ctx);
Boolean eap_peer_get_eapResp(struct eap_peer_ctx* eap_ctx);
void eap_peer_set_eapResp(struct eap_peer_ctx* eap_ctx, Boolean value);
struct wpabuf *eap_peer_get_eapRespData(struct eap_peer_ctx* eap_ctx);
Boolean eap_peer_get_eapSuccess(struct eap_peer_ctx* eap_ctx);
void eap_peer_set_eapSuccess(struct eap_peer_ctx* eap_ctx, Boolean value);
Boolean eap_peer_get_eapFail(struct eap_peer_ctx* eap_ctx);
void eap_peer_set_eapFail(struct eap_peer_ctx* eap_ctx, Boolean value);
Boolean eap_peer_get_eapKeyAvailable(struct eap_peer_ctx* eap_ctx);
u8 *eap_peer_get_eapKeyData(struct eap_peer_ctx* eap_ctx, size_t *key_len);

#endif
