/*
 *  eap_peer_interface.c
 *  
 *
 *  Created by Rafa Marin Lopez on 27/10/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 */

#include "eap_peer_interface.h"


static struct eap_peer_config * peer_get_config(void *ctx)
{
	struct eap_peer_ctx *peer = ctx;
	return &peer->eap_config;
}


static Boolean peer_get_bool(void *ctx, enum eapol_bool_var variable)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return FALSE;
	switch (variable) {
		case EAPOL_eapSuccess:
			return peer->eapSuccess;
		case EAPOL_eapRestart:
			return peer->eapRestart;
		case EAPOL_eapFail:
			return peer->eapFail;
		case EAPOL_eapResp:
			return peer->eapResp;
		case EAPOL_eapNoResp:
			return peer->eapNoResp;
		case EAPOL_eapReq:
			return peer->eapReq;
		case EAPOL_portEnabled:
			return peer->portEnabled;
		case EAPOL_altAccept:
			return peer->altAccept;
		case EAPOL_altReject:
			return peer->altReject;
	}
	return FALSE;
}


static void peer_set_bool(void *ctx, enum eapol_bool_var variable,
						  Boolean value)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return;
	switch (variable) {
		case EAPOL_eapSuccess:
			peer->eapSuccess = value;
			break;
		case EAPOL_eapRestart:
			peer->eapRestart = value;
			break;
		case EAPOL_eapFail:
			peer->eapFail = value;
			break;
		case EAPOL_eapResp:
			peer->eapResp = value;
			break;
		case EAPOL_eapNoResp:
			peer->eapNoResp = value;
			break;
		case EAPOL_eapReq:
			peer->eapReq = value;
			break;
		case EAPOL_portEnabled:
			peer->portEnabled = value;
			break;
		case EAPOL_altAccept:
			peer->altAccept = value;
			break;
		case EAPOL_altReject:
			peer->altReject = value;
			break;
	}
}


static unsigned int peer_get_int(void *ctx, enum eapol_int_var variable)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return 0;
	switch (variable) {
		case EAPOL_idleWhile:
			return peer->idleWhile;
	}
	return 0;
}


static void peer_set_int(void *ctx, enum eapol_int_var variable,
						 unsigned int value)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return;
	switch (variable) {
		case EAPOL_idleWhile:
			peer->idleWhile = value;
			break;
	}
}


static struct wpabuf * peer_get_eapReqData(void *ctx)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL || peer->eapReqData == NULL)
		return NULL;
	
	return peer->eapReqData;
}


static void peer_set_config_blob(void *ctx, struct wpa_config_blob *blob)
{
	printf("TODO: %s\n", __func__);
}


static const struct wpa_config_blob *
peer_get_config_blob(void *ctx, const char *name)
{
	printf("TODO: %s\n", __func__);
	return NULL;
}


static void peer_notify_pending(void *ctx)
{
	printf("TODO: %s\n", __func__);
}


static int eap_peer_register_methods(struct eap_method **eap_methods)
{
	int ret = 0;
	
#ifdef EAP_MD5
	if (ret == 0)
		ret = eap_peer_md5_register(eap_methods);
#endif /* EAP_MD5 */
	
#ifdef EAP_TLS
	if (ret == 0)
		ret = eap_peer_tls_register(eap_methods);
#endif /* EAP_TLS */
	
#ifdef EAP_MSCHAPv2
	if (ret == 0)
		ret = eap_peer_mschapv2_register(eap_methods);
#endif /* EAP_MSCHAPv2 */
	
#ifdef EAP_PEAP
	if (ret == 0)
		ret = eap_peer_peap_register(eap_methods);
#endif /* EAP_PEAP */
	
#ifdef EAP_TTLS
	if (ret == 0)
		ret = eap_peer_ttls_register(eap_methods);
#endif /* EAP_TTLS */
	
#ifdef EAP_GTC
	if (ret == 0)
		ret = eap_peer_gtc_register(eap_methods);
#endif /* EAP_GTC */
	
#ifdef EAP_OTP
	if (ret == 0)
		ret = eap_peer_otp_register(eap_methods);
#endif /* EAP_OTP */
	
#ifdef EAP_SIM
	if (ret == 0)
		ret = eap_peer_sim_register(eap_methods);
#endif /* EAP_SIM */
	
#ifdef EAP_LEAP
	if (ret == 0)
		ret = eap_peer_leap_register(eap_methods);
#endif /* EAP_LEAP */
	
#ifdef EAP_PSK
	if (ret == 0)
		ret = eap_peer_psk_register(eap_methods);
#endif /* EAP_PSK */
	
#ifdef EAP_AKA
	if (ret == 0)
		ret = eap_peer_aka_register(eap_methods);
#endif /* EAP_AKA */
	
#ifdef EAP_AKA_PRIME
	if (ret == 0)
		ret = eap_peer_aka_prime_register(eap_methods);
#endif /* EAP_AKA_PRIME */
	
#ifdef EAP_FAST
	if (ret == 0)
		ret = eap_peer_fast_register(eap_methods);
#endif /* EAP_FAST */
	
#ifdef EAP_PAX
	if (ret == 0)
		ret = eap_peer_pax_register(eap_methods);
#endif /* EAP_PAX */
	
#ifdef EAP_SAKE
	if (ret == 0)
		ret = eap_peer_sake_register(eap_methods);
#endif /* EAP_SAKE */
	
#ifdef EAP_GPSK
	if (ret == 0)
		ret = eap_peer_gpsk_register(eap_methods);
#endif /* EAP_GPSK */
	
#ifdef EAP_WSC
	if (ret == 0)
		ret = eap_peer_wsc_register(eap_methods);
#endif /* EAP_WSC */
	
#ifdef EAP_IKEV2
	if (ret == 0)
		ret = eap_peer_ikev2_register(eap_methods);
#endif /* EAP_IKEV2 */
	
#ifdef EAP_VENDOR_TEST
	if (ret == 0)
		ret = eap_peer_vendor_test_register(eap_methods);
#endif /* EAP_VENDOR_TEST */
	
#ifdef EAP_TNC
	if (ret == 0)
		ret = eap_peer_tnc_register(eap_methods);
#endif /* EAP_TNC */
	
	return ret;
}

int eap_peer_init(struct eap_peer_ctx *eap_ctx, void *eap_ll_ctx, char * user, char * passwd, char * cacert, char * ccert, char * ckey, char * pkey, char * fsize)
{
	struct eapol_callbacks * eap_cb = (struct eapol_callbacks *)os_malloc(sizeof(struct eapol_callbacks));
	os_memset(eap_cb, 0, sizeof(*eap_cb));
	eap_cb->get_config = peer_get_config;
	eap_cb->get_bool = peer_get_bool;
	eap_cb->set_bool = peer_set_bool;
	eap_cb->get_int = peer_get_int;
	eap_cb->set_int = peer_set_int;
	eap_cb->get_eapReqData = peer_get_eapReqData;
	eap_cb->set_config_blob = peer_set_config_blob;
	eap_cb->get_config_blob = peer_get_config_blob;
	eap_cb->notify_pending = peer_notify_pending;
	
	os_memset(eap_ctx, 0, sizeof(*eap_ctx));
	
	if (eap_peer_register_methods(&(eap_ctx->eap_methods)) < 0)
	{
		return -1;
    }

	struct eap_config *eap_conf=(struct eap_config *)os_malloc(sizeof(struct eap_config));
	os_memset(eap_conf, 0, sizeof(*eap_conf));
	eap_conf->eap_methods=eap_ctx->eap_methods; //This is new.
	
	eap_ctx->eap_config.identity = (u8 *) os_strdup(user);
	eap_ctx->eap_config.identity_len = strlen(user);
	eap_ctx->eap_config.password = (u8 *) os_strdup(passwd);
	eap_ctx->eap_config.password_len = strlen(passwd);
	eap_ctx->eap_config.client_cert = (u8*) os_strdup(ccert);
	eap_ctx->eap_config.private_key=(u8*) os_strdup(ckey);
	eap_ctx->eap_config.ca_cert = (u8 *) os_strdup(cacert);
	eap_ctx->eap_config.private_key_passwd = (u8*) os_strdup(pkey);
	eap_ctx->eap_config.fragment_size = fsize;
	
	eap_ctx->eap = eap_peer_sm_init(eap_ctx, eap_cb, eap_ctx, eap_conf);
	if (eap_ctx->eap == NULL)
		return -1;
	
	eap_ctx->eap_ll_ctx = eap_ll_ctx;
	
	/* Enable "port" to allow authentication */
	eap_ctx->portEnabled = TRUE;
	
	return 0;
}

void eap_peer_deinit(struct eap_peer_ctx *eap_ctx,struct eap_method **eap_methods)
{
	eap_peer_sm_deinit(eap_ctx->eap);
	eap_peer_unregister_methods(eap_methods);
	wpabuf_free(eap_ctx->eapReqData);
	os_free(eap_ctx->eap_config.identity);
	os_free(eap_ctx->eap_config.password);
	os_free(eap_ctx->eap_config.ca_cert);
}


int eap_peer_step(struct eap_peer_ctx *eap_ctx)
{
	return eap_peer_sm_step(eap_ctx->eap);
}

void eap_peer_set_eapReq(struct eap_peer_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eapReq = value;
}

void eap_peer_set_eapReqData(struct eap_peer_ctx* eap_ctx, const u8 *eap_packet, size_t eap_packet_len)
{
	wpabuf_free(eap_ctx->eapReqData);
	eap_ctx->eapReqData = wpabuf_alloc_copy(eap_packet, eap_packet_len);
}

void eap_peer_set_portEnabled(struct eap_peer_ctx* eap_ctx, Boolean value)
{
	eap_ctx->portEnabled = value;
}

void eap_peer_set_idleWhile(struct eap_peer_ctx* eap_ctx, unsigned int idleWhile)
{
	eap_ctx->idleWhile = idleWhile;
}

void eap_peer_set_eapRestart(struct eap_peer_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eapRestart = value;
}

Boolean eap_peer_get_altReject(struct eap_peer_ctx* eap_ctx)
{
	return eap_ctx->altReject;
}

Boolean eap_peer_get_altAccept(struct eap_peer_ctx* eap_ctx)
{
	return eap_ctx->altAccept;
}

Boolean eap_peer_get_eapResp(struct eap_peer_ctx* eap_ctx)
{
	return eap_ctx->eapResp;
}

void eap_peer_set_eapResp(struct eap_peer_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eapResp = value;
}

struct wpabuf *eap_peer_get_eapRespData(struct eap_peer_ctx* eap_ctx)
{
	return eap_get_eapRespData(eap_ctx->eap);
}

Boolean eap_peer_get_eapSuccess(struct eap_peer_ctx* eap_ctx)
{
	return eap_ctx->eapSuccess;
}

void eap_peer_set_eapSuccess(struct eap_peer_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eapSuccess = value;
}

Boolean eap_peer_get_eapFail(struct eap_peer_ctx* eap_ctx)
{
	return eap_ctx->eapFail;
}

void eap_peer_set_eapFail(struct eap_peer_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eapFail = value;
}

Boolean eap_peer_get_eapKeyAvailable(struct eap_peer_ctx* eap_ctx)
{
	return eap_key_available(eap_ctx->eap);
}


u8 *eap_peer_get_eapKeyData(struct eap_peer_ctx* eap_ctx, size_t *key_len)
{
	return eap_get_eapKeyData(eap_ctx->eap, key_len);
}






