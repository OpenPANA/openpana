#include "eap_auth_interface.h"
#include "../utils/os.h"

struct radius_ctx *global_rad_ctx=NULL;
pthread_mutex_t radmutex;
pthread_mutex_t radmutex_list;

static char *eap_type_text(u8 type)
{
	switch (type) {
		case EAP_TYPE_IDENTITY: return "Identity";
		case EAP_TYPE_NOTIFICATION: return "Notification";
		case EAP_TYPE_NAK: return "Nak";
		case EAP_TYPE_TLS: return "TLS";
		case EAP_TYPE_TTLS: return "TTLS";
		case EAP_TYPE_PEAP: return "PEAP";
		case EAP_TYPE_SIM: return "SIM";
		case EAP_TYPE_GTC: return "GTC";
		case EAP_TYPE_MD5: return "MD5";
		case EAP_TYPE_OTP: return "OTP";
		case EAP_TYPE_FAST: return "FAST";
		case EAP_TYPE_SAKE: return "SAKE";
		case EAP_TYPE_PSK: return "PSK";
		default: return "Unknown";
	}
}


static int add_extra_attr(struct radius_msg *msg,
						  struct extra_radius_attr *attr)
{
	size_t len;
	char *pos;
	u32 val;
	char buf[128];
	
	switch (attr->syntax) {
		case 's':
			os_snprintf(buf, sizeof(buf), "%s", attr->data);
			len = os_strlen(buf);
			break;
		case 'n':
			buf[0] = '\0';
			len = 1;
			break;
		case 'x':
			pos = attr->data;
			if (pos[0] == '0' && pos[1] == 'x')
				pos += 2;
			len = os_strlen(pos);
			if ((len & 1) || (len / 2) > sizeof(buf)) {
				printf("Invalid extra attribute hexstring\n");
				return -1;
			}
			len /= 2;
			if (hexstr2bin(pos, (u8 *) buf, len) < 0) {
				printf("Invalid extra attribute hexstring\n");
				return -1;
			}
			break;
		case 'd':
			val = htonl(atoi(attr->data));
			os_memcpy(buf, &val, 4);
			len = 4;
			break;
		default:
			printf("Incorrect extra attribute syntax specification\n");
			return -1;
	}
	
	if (!radius_msg_add_attr(msg, attr->type, (u8 *) buf, len)) {
		printf("Could not add attribute %d\n", attr->type);
		return -1;
	}

	return 0;
}

static int add_extra_attrs(struct radius_msg *msg,
						   struct extra_radius_attr *attrs)
{
	struct extra_radius_attr *p;
	for (p = attrs; p; p = p->next) {
		if (add_extra_attr(msg, p) < 0){
			return -1;
		}
	}

	return 0;
}


static struct extra_radius_attr *
find_extra_attr(struct extra_radius_attr *attrs, u8 type)
{
	struct extra_radius_attr *p;
	for (p = attrs; p; p = p->next) {
		if (p->type == type)
			return p;
	}
	return NULL;
}


static void eap_auth_encapsulate_radius(struct eap_auth_ctx *eap_ctx, const struct wpabuf *eap_buf)
{

		struct radius_ctx *radctx= eap_ctx->rad_ctx;
		
		
		struct radius_msg *msg;
		char buf[128];
		u8 *eap;
		size_t len;
		const struct eap_hdr *hdr;
		const u8 *pos;
    	
		eap = wpabuf_head(eap_buf);
		len = wpabuf_len(eap_buf);
		
		wpa_printf(MSG_DEBUG, "Encapsulating EAP message into a RADIUS "
				   "packet");
		
		
		
		/*We enter the critical section to prepare a message to be sent*/
		
		
		eap_ctx->radius_identifier = radius_client_get_id(radctx->radius);		
		
		msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST,
							 eap_ctx->radius_identifier);

		
		if (msg == NULL) {
			printf("Could not create net RADIUS packet\n");
			return;
		}
		
		radius_msg_make_authenticator(msg, (u8 *) eap_ctx, sizeof(*eap_ctx));
		
		hdr = (const struct eap_hdr *) eap;
		pos = (const u8 *) (hdr + 1);
		if (len > sizeof(*hdr) && hdr->code == EAP_CODE_RESPONSE &&
			pos[0] == EAP_TYPE_IDENTITY) {
			pos++;
			os_free(eap_ctx->eap_identity);
			eap_ctx->eap_identity_len = len - sizeof(*hdr) - 1;
			eap_ctx->eap_identity = os_malloc(eap_ctx->eap_identity_len);
			if (eap_ctx->eap_identity) {
				os_memcpy(eap_ctx->eap_identity, pos, eap_ctx->eap_identity_len);
				wpa_hexdump(MSG_DEBUG, "Learned identity from "
							"EAP-Response-Identity",
							eap_ctx->eap_identity, eap_ctx->eap_identity_len);
			}
		}
		
		if (eap_ctx->eap_identity &&
			!radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME,
								 eap_ctx->eap_identity, eap_ctx->eap_identity_len)) {
				printf("Could not add User-Name\n");
				goto fail;
			}
		
		if (!find_extra_attr(radctx->extra_attrs, RADIUS_ATTR_NAS_IP_ADDRESS) &&
			!radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
								 (u8 *) &radctx->own_ip_addr, 4)) {
				printf("Could not add NAS-IP-Address\n");
				goto fail;
			}
		
		os_snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT, MAC2STR(eap_ctx->own_addr));
		if (!find_extra_attr(radctx->extra_attrs, RADIUS_ATTR_CALLING_STATION_ID)
			&&
			!radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
								 (u8 *) buf, os_strlen(buf))) {
				printf("Could not add Calling-Station-Id\n");
				goto fail;
			}
		
		/* TODO: should probably check MTU from driver config; 2304 is max for
		 * IEEE 802.11, but use 1400 to avoid problems with too large packets
		 */
		if (!find_extra_attr(radctx->extra_attrs, RADIUS_ATTR_FRAMED_MTU) &&
			!radius_msg_add_attr_int32(msg, RADIUS_ATTR_FRAMED_MTU, 1400)) {
			printf("Could not add Framed-MTU\n");
			goto fail;
		}
		
		if (!find_extra_attr(radctx->extra_attrs, RADIUS_ATTR_NAS_PORT_TYPE) &&
			!radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT_TYPE,
									   RADIUS_NAS_PORT_TYPE_IEEE_802_11)) {
				printf("Could not add NAS-Port-Type\n");
				goto fail;
			}
		
		os_snprintf(buf, sizeof(buf), "%s", radctx->connect_info);
		if (!find_extra_attr(radctx->extra_attrs, RADIUS_ATTR_CONNECT_INFO) &&
			!radius_msg_add_attr(msg, RADIUS_ATTR_CONNECT_INFO,
								 (u8 *) buf, os_strlen(buf))) {
				printf("Could not add Connect-Info\n");
				goto fail;
			}
		
		if (add_extra_attrs(msg, radctx->extra_attrs) < 0)
			goto fail;
		
		if (eap && !radius_msg_add_eap(msg, eap, len)) {
			printf("Could not add EAP-Message\n");
			goto fail;
		}
		
		/* State attribute must be copied if and only if this packet is
		 * Access-Request reply to the previous Access-Challenge */
		
		if (eap_ctx->last_recv_radius &&
			radius_msg_get_hdr(eap_ctx->last_recv_radius)->code ==
			RADIUS_CODE_ACCESS_CHALLENGE) {
			int res = radius_msg_copy_attr(msg, eap_ctx->last_recv_radius,
										   RADIUS_ATTR_STATE);
			if (res < 0) {
				printf("Could not copy State attribute from previous "
					   "Access-Challenge\n");
				goto fail;
			}
			if (res > 0) {
				wpa_printf(MSG_DEBUG, "  Copied RADIUS State "
						   "Attribute");
			}
		}
		
		//FIXME: PEDRO: Actualiza el valor del último mensaje enviado y del socket a enviar
		eap_ctx->last_send_radius = msg;
		
		radius_client_send(radctx->radius, msg, RADIUS_AUTH, eap_ctx->own_addr,(void *)eap_ctx);
		return;
		
	fail:
		radius_msg_free(msg);
}


static void eap_auth_get_keys(struct eap_auth_ctx *eap_ctx,
								struct radius_msg *msg, struct radius_msg *req,
								const u8 *shared_secret,
								size_t shared_secret_len)
{
	struct radius_ms_mppe_keys *keys;
	
	keys = radius_msg_get_ms_keys(msg, req, shared_secret,
								  shared_secret_len);
	if (keys && keys->send == NULL && keys->recv == NULL) {
		os_free(keys);
		keys = radius_msg_get_cisco_keys(msg, req, shared_secret,
										 shared_secret_len);
	}
	
	if (keys) 
	{
		if (keys->send) {
			wpa_hexdump(MSG_DEBUG, "MS-MPPE-Send-Key (sign)",
						keys->send, keys->send_len);
		}
		if (keys->recv) 
		{
			wpa_hexdump(MSG_DEBUG, "MS-MPPE-Recv-Key (crypt)",
						keys->recv, keys->recv_len);
			
			if (keys->recv_len + keys->send_len == 64)
			{
				os_free(eap_ctx->eap_if->aaaEapKeyData);
				eap_ctx->eap_if->aaaEapKeyData = os_malloc(64);
				if (eap_ctx->eap_if->aaaEapKeyData) 
				{
					os_memcpy(eap_ctx->eap_if->aaaEapKeyData, keys->recv,
							  keys->recv_len);
					os_memcpy(eap_ctx->eap_if->aaaEapKeyData + keys->recv_len,
							  keys->send, keys->send_len);
					eap_ctx->eap_if->aaaEapKeyDataLen = keys->recv_len + keys->send_len;
					eap_ctx->eap_if->aaaEapKeyAvailable = TRUE;
				}	
				
				/*eap_ctx->authenticator_msk_len = 64;
				
				os_memcpy(eap_ctx->authenticator_msk, keys->recv,
						  keys->recv_len);
				os_memcpy(&(eap_ctx->authenticator_msk[32]),keys->send,keys->send_len);*/
			}
		}
		os_free(keys->send);
		os_free(keys->recv);
		os_free(keys);	
		
	} 
}


static void eap_auth_decapsulate_radius(struct eap_auth_ctx *eap_ctx)
{
	u8 *eap;
	size_t len;
	struct eap_hdr *hdr;
	int eap_type = -1;
	char buf[64];
	struct radius_msg *msg;
	
	if (eap_ctx->last_recv_radius == NULL){
		return;
	}

	msg = eap_ctx->last_recv_radius;
	
	eap = radius_msg_get_eap(msg, &len);
	if (eap == NULL) {
		/* draft-aboba-radius-rfc2869bis-20.txt, Chap. 2.6.3:
		 * RADIUS server SHOULD NOT send Access-Reject/no EAP-Message
		 * attribute */
		wpa_printf(MSG_DEBUG, "could not extract "
			       "EAP-Message from RADIUS message");
		return;
	}
	
	if (len < sizeof(*hdr)) {
		wpa_printf(MSG_DEBUG, "too short EAP packet "
			       "received from authentication server");
		os_free(eap);
		return;
	}
	
	if (len > sizeof(*hdr))
		eap_type = eap[sizeof(*hdr)];
	
	hdr = (struct eap_hdr *) eap;
	switch (hdr->code) {
		case EAP_CODE_REQUEST:
			os_snprintf(buf, sizeof(buf), "EAP-Request-%s (%d)",
						eap_type >= 0 ? eap_type_text(eap_type) : "??",
						eap_type);
			break;
		case EAP_CODE_RESPONSE:
			os_snprintf(buf, sizeof(buf), "EAP Response-%s (%d)",
						eap_type >= 0 ? eap_type_text(eap_type) : "??",
						eap_type);
			break;
		case EAP_CODE_SUCCESS:
			os_strlcpy(buf, "EAP Success", sizeof(buf));
			/* LEAP uses EAP Success within an authentication, so must not
			 * stop here with eloop_terminate(); */
			break;
		case EAP_CODE_FAILURE:
			os_strlcpy(buf, "EAP Failure", sizeof(buf));
			//eloop_terminate();
			break;
		default:
			os_strlcpy(buf, "unknown EAP code", sizeof(buf));
			wpa_hexdump(MSG_DEBUG, "Decapsulated EAP packet", eap, len);
			break;
	}
	wpa_printf(MSG_DEBUG, "decapsulated EAP packet (code=%d "
		       "id=%d len=%d) from RADIUS server: %s",
			   hdr->code, hdr->identifier, ntohs(hdr->length), buf);
	
	eap_ctx->eap_if->aaaEapReq = TRUE;
	
	wpabuf_free(eap_ctx->eap_if->aaaEapReqData);
	eap_ctx->eap_if->aaaEapReqData = wpabuf_alloc_ext_data(eap, len);
	
}


/* Process the RADIUS frames from Authentication Server */
static RadiusRxResult
eap_auth_receive_radius(struct radius_msg *msg, struct radius_msg *req,
						const u8 *shared_secret, size_t shared_secret_len,
						void *data)
{
	pthread_mutex_lock(&radmutex);
	
	int override_eapReq = 0;
	u32 session_timeout = 0, termination_action, acct_interim_interval;
	int session_timeout_set, old_vlanid = 0;

	struct radius_ctx *radctx = data; /*This is going to be the general rad_ctx*/
	struct radius_hdr *hdr = radius_msg_get_hdr(msg);
	
	/*Now, we should look for the identity in a list of eap_auth contexts*/

	struct eap_auth_ctx *eap_ctx = search_eap_ctx_rad_client(hdr->identifier); //Search for the correct eap_ctx
	//struct eap_auth_ctx *eap_ctx = radctx->eap_ctx; /*radctx->eap_ctx will be a pointer to linked list*/
	
	/*-----------------------------------------------------------------*/
	
	
	/* RFC 2869, Ch. 5.13: valid Message-Authenticator attribute MUST be
	 * present when packet contains an EAP-Message attribute */
	if (hdr->code == RADIUS_CODE_ACCESS_REJECT &&
	    radius_msg_get_attr(msg, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, NULL,
							0) < 0 &&
	    radius_msg_get_attr(msg, RADIUS_ATTR_EAP_MESSAGE, NULL, 0) < 0) {
		wpa_printf(MSG_DEBUG, "Allowing RADIUS "
				   "Access-Reject without Message-Authenticator "
				   "since it does not include EAP-Message\n");
	} else if (radius_msg_verify(msg, shared_secret, shared_secret_len,
								 req, 1)) {
		printf("Incoming RADIUS packet did not have correct "
		       "Message-Authenticator - dropped\n");
		pthread_mutex_unlock(&radmutex);
		return RADIUS_RX_UNKNOWN;
	}
	
	if (hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
	    hdr->code != RADIUS_CODE_ACCESS_REJECT &&
	    hdr->code != RADIUS_CODE_ACCESS_CHALLENGE) {
		printf("Unknown RADIUS message code\n");
		pthread_mutex_unlock(&radmutex);
		return RADIUS_RX_UNKNOWN;
	}
	
	/*Rafa: Here we have to find out the session that sends the RADIUS request that corresponds to this answer*/
	/*To do this, we have to look for in the session list the session that session->radius_identifier == msg->identifier*/
	
	
	/*********************************************************************************************/
	//eap_ctx = search_eap_ctx_rad_client(hdr->identifier);
	//eap_ctx->radius_identifier = -1; //PEDRO: Esto es lo que estaba puesto
	wpa_printf(MSG_DEBUG, "RADIUS packet matching with station");

	//if (eap_ctx->last_recv_radius != NULL){
		//radius_msg_free(eap_ctx->last_recv_radius); //fixme: This line must be uncommented?
	//}
	eap_ctx->last_recv_radius = malloc (1024);
	memcpy(eap_ctx->last_recv_radius, msg, 1024);
	//eap_ctx->last_recv_radius = msg;

	session_timeout_set = !radius_msg_get_attr_int32(msg, RADIUS_ATTR_SESSION_TIMEOUT,
							                         &session_timeout);
	
	if (radius_msg_get_attr_int32(msg, RADIUS_ATTR_TERMINATION_ACTION,&termination_action))
		termination_action = RADIUS_TERMINATION_ACTION_DEFAULT;
	
	/**TBD*
	 if (hapd->conf->acct_interim_interval == 0 &&
	 hdr->code == RADIUS_CODE_ACCESS_ACCEPT &&
	 radius_msg_get_attr_int32(msg, RADIUS_ATTR_ACCT_INTERIM_INTERVAL,
	 &acct_interim_interval) == 0) {
	 if (acct_interim_interval < 60) {
	 hostapd_logger(hapd, sta->addr,
	 HOSTAPD_MODULE_IEEE8021X,
	 HOSTAPD_LEVEL_INFO,
	 "ignored too small "
	 "Acct-Interim-Interval %d",
	 acct_interim_interval);
	 } else
	 sta->acct_interim_interval = acct_interim_interval;
	 }*/
	
	switch (hdr->code) {
		case RADIUS_CODE_ACCESS_ACCEPT:
			/*TBD: if (sta->ssid->dynamic_vlan == DYNAMIC_VLAN_DISABLED)
				sta->vlan_id = 0;
#ifndef CONFIG_NO_VLAN
			else {
				old_vlanid = sta->vlan_id;
				sta->vlan_id = radius_msg_get_vlanid(msg);
			}
			if (sta->vlan_id > 0 &&
				hostapd_get_vlan_id_ifname(hapd->conf->vlan,
										   sta->vlan_id)) {
					hostapd_logger(hapd, sta->addr,
								   HOSTAPD_MODULE_RADIUS,
								   HOSTAPD_LEVEL_INFO,
								   "VLAN ID %d", sta->vlan_id);
				} else if (sta->ssid->dynamic_vlan == DYNAMIC_VLAN_REQUIRED) {
					sta->eapol_sm->authFail = TRUE;
					hostapd_logger(hapd, sta->addr,
								   HOSTAPD_MODULE_IEEE8021X,
								   HOSTAPD_LEVEL_INFO, "authentication "
								   "server did not include required VLAN "
								   "ID in Access-Accept");
					break;
				}
#endif 
			
			ap_sta_bind_vlan(hapd, sta, old_vlanid);
			
			-- RFC 3580, Ch. 3.17 --
			if (session_timeout_set && termination_action ==
				RADIUS_TERMINATION_ACTION_RADIUS_REQUEST) {
				sm->reAuthPeriod = session_timeout;
			} else if (session_timeout_set)
				ap_sta_session_timeout(hapd, sta, session_timeout);*/
			
			eap_ctx->eap_if->aaaSuccess = TRUE;
			override_eapReq = 1;
			eap_auth_get_keys(eap_ctx, msg, req, shared_secret,
								shared_secret_len);
			break;
		case RADIUS_CODE_ACCESS_REJECT:
			eap_ctx->radius_access_reject_received = 1;
			eap_ctx->eap_if->aaaFail = TRUE;
			override_eapReq = 1;
			break;
	}

	eap_auth_decapsulate_radius(eap_ctx);
	
	/*Rafa: This source code may be removed*/
	if ((hdr->code == RADIUS_CODE_ACCESS_ACCEPT &&
	     eap_ctx->radius_num_reauths < 0) ||
	    hdr->code == RADIUS_CODE_ACCESS_REJECT) {
		//eloop_terminate();
	}
	/*******************************************/
	
	
	if (override_eapReq){
		eap_ctx->eap_if->aaaEapReq = FALSE;
	}
	
	eap_server_sm_step(eap_ctx->eap);

	pthread_mutex_unlock(&radmutex);
	return RADIUS_RX_QUEUED;
}



static int server_get_eap_user(void *ctx, const u8 *identity,
							   size_t identity_len, int phase2,
							   struct eap_user *user)
{
	os_memset(user, 0, sizeof(*user));
	
	if (!phase2) {
		/* Only allow EAP-PEAP as the Phase 1 method */
		user->methods[0].vendor = EAP_VENDOR_IETF;
		user->methods[0].method = EAP_TYPE_PEAP;
		return 0;
	}
	
	if (identity_len != 4 || identity == NULL ||
	    os_memcmp(identity, "user", 4) != 0) {
		printf("Unknown user\n");
		return -1;
	}
	
	/* Only allow EAP-MSCHAPv2 as the Phase 2 method */
	user->methods[0].vendor = EAP_VENDOR_IETF;
	user->methods[0].method = EAP_TYPE_MSCHAPV2;
	user->password = (u8 *) os_strdup("password");
	user->password_len = 8;
	
	return 0;
}

static const char * server_get_eap_req_id_text(void *ctx, size_t *len)
{
	*len = 0;
	return NULL;
}

/**This is for the standalone authenticator**/
static int eap_server_register_methods(struct eap_method **eap_methods)
{
	int ret = 0;
#ifdef EAP_SERVER_IDENTITY
	if (ret == 0)
		ret = eap_server_identity_register(eap_methods);
#endif /* EAP_SERVER_IDENTITY */
	
#ifdef EAP_SERVER_MD5
	if (ret == 0)
		ret = eap_server_md5_register(eap_methods);
#endif /* EAP_SERVER_MD5 */
	
#ifdef EAP_SERVER_TLS
	if (ret == 0)
		ret = eap_server_tls_register(eap_methods);
#endif /* EAP_SERVER_TLS */
	
#ifdef EAP_SERVER_MSCHAPV2
	if (ret == 0)
		ret = eap_server_mschapv2_register(eap_methods);
#endif /* EAP_SERVER_MSCHAPV2 */
	
#ifdef EAP_SERVER_PEAP
	if (ret == 0)
		ret = eap_server_peap_register(eap_methods);
#endif /* EAP_SERVER_PEAP */
	
#ifdef EAP_SERVER_TLV
	if (ret == 0)
		ret = eap_server_tlv_register(eap_methods);
#endif /* EAP_SERVER_TLV */
	
#ifdef EAP_SERVER_GTC
	if (ret == 0)
		ret = eap_server_gtc_register(eap_methods);
#endif /* EAP_SERVER_GTC */
	
#ifdef EAP_SERVER_TTLS
	if (ret == 0)
		ret = eap_server_ttls_register(eap_methods);
#endif /* EAP_SERVER_TTLS */
	
#ifdef EAP_SERVER_SIM
	if (ret == 0)
		ret = eap_server_sim_register(eap_methods);
#endif /* EAP_SERVER_SIM */
	
#ifdef EAP_SERVER_AKA
	if (ret == 0)
		ret = eap_server_aka_register(eap_methods);
#endif /* EAP_SERVER_AKA */
	
#ifdef EAP_SERVER_AKA_PRIME
	if (ret == 0)
		ret = eap_server_aka_prime_register(eap_methods);
#endif /* EAP_SERVER_AKA_PRIME */
	
#ifdef EAP_SERVER_PAX
	if (ret == 0)
		ret = eap_server_pax_register(eap_methods);
#endif /* EAP_SERVER_PAX */
	
#ifdef EAP_SERVER_PSK
	if (ret == 0)
		ret = eap_server_psk_register(eap_methods);
#endif /* EAP_SERVER_PSK */
	
#ifdef EAP_SERVER_SAKE
	if (ret == 0)
		ret = eap_server_sake_register(eap_methods);
#endif /* EAP_SERVER_SAKE */
	
#ifdef EAP_SERVER_GPSK
	if (ret == 0)
		ret = eap_server_gpsk_register(eap_methods);
#endif /* EAP_SERVER_GPSK */
	
#ifdef EAP_SERVER_VENDOR_TEST
	if (ret == 0)
		ret = eap_server_vendor_test_register(eap_methods);
#endif /* EAP_SERVER_VENDOR_TEST */
	
#ifdef EAP_SERVER_FAST
	if (ret == 0)
		ret = eap_server_fast_register(eap_methods);
#endif /* EAP_SERVER_FAST */
	
#ifdef EAP_SERVER_WSC
	if (ret == 0)
		ret = eap_server_wsc_register(eap_methods);
#endif /* EAP_SERVER_WSC */
	
#ifdef EAP_SERVER_IKEV2
	if (ret == 0)
		ret = eap_server_ikev2_register(eap_methods);
#endif /* EAP_SERVER_IKEV2 */
	
#ifdef EAP_SERVER_TNC
	if (ret == 0)
		ret = eap_server_tnc_register(eap_methods);
#endif /* EAP_SERVER_TNC */
	
	return ret;
}

static int eap_auth_init_tls(struct eap_auth_ctx *eap_ctx)
{
	struct tls_config tconf;
	struct tls_connection_params tparams;
	
	os_memset(&tconf, 0, sizeof(tconf));
	eap_ctx->tls_ctx = tls_init(&tconf);
	if (eap_ctx->tls_ctx == NULL){
		return -1;
	}
	
	os_memset(&tparams, 0, sizeof(tparams));
	tparams.ca_cert = "ca.pem";
	tparams.client_cert = "server.pem";
	/* tparams.private_key = "server.key"; */
	tparams.private_key = "server-key.pem";
	/* tparams.private_key_passwd = "whatever"; */
	
	if (tls_global_set_params(eap_ctx->tls_ctx, &tparams)) {
		printf("Failed to set TLS parameters\n");
		return -1;
	}
	
	if (tls_global_set_verify(eap_ctx->tls_ctx, 0)) {
		printf("Failed to set check_crl\n");
		return -1;
	}

	return 0;
}

struct radius_ctx *rad_client_init()
{
	char *as_addr = "127.0.0.1";
	int as_port = 1812;
	char *as_secret = "testing123";
	char *cli_addr = NULL;
	
	struct extra_radius_attr *p = NULL, *p1;
	struct hostapd_radius_server *srv;
	struct radius_ctx *rad_ctx = global_rad_ctx;
	
	if (rad_ctx == NULL)
	{			
		rad_ctx = os_zalloc(sizeof(struct radius_ctx));
		if (rad_ctx == NULL) return NULL;
		os_memset(rad_ctx, 0, sizeof(*rad_ctx));
	
		pthread_mutex_init(&radmutex, NULL);
		pthread_mutex_init(&radmutex_list, NULL);
	
		inet_aton("127.0.0.1", &rad_ctx->own_ip_addr);
		rad_ctx->own_addr[0]=0x00;
		rad_ctx->own_addr[1]=0x00;
		rad_ctx->own_addr[2]=0x00;
		rad_ctx->own_addr[3]=0x00;
		rad_ctx->own_addr[4]=0x00;
		rad_ctx->own_addr[5]=0x00;
	
		rad_ctx->connect_info=os_zalloc(sizeof("CONNECT 11Mbps 802.11b")+1);
		os_snprintf(rad_ctx->connect_info, sizeof(rad_ctx->connect_info), "%s", "CONNECT 11Mbps 802.11b");
	
		srv = os_zalloc(sizeof(*srv));
		if (srv == NULL)	
			return NULL;
	
		srv->addr.af = AF_INET;
		srv->port = 1812;
		if (hostapd_parse_ip_addr("127.0.0.1", &srv->addr) < 0) {
			printf("Failed to parse IP address\n");
			return NULL;
		}
		srv->shared_secret = (u8 *) os_strdup("testing123"); //Rafa: Obtain this password from a file
		srv->shared_secret_len = 10;
	
		rad_ctx->conf.auth_server = rad_ctx->conf.auth_servers = srv;
		rad_ctx->conf.num_auth_servers = 1;
		rad_ctx->conf.msg_dumps = 1;
	
		rad_ctx->radius = radius_client_init(rad_ctx, &(rad_ctx->conf));
		if (rad_ctx->radius == NULL) {
			printf("Failed to initialize RADIUS client\n");
			return NULL;
		}
	
	/*Rafa: we should remove this so the network manager thread will wait for receiving something*/
	
		if (radius_client_register(rad_ctx->radius, RADIUS_AUTH, eap_auth_receive_radius, rad_ctx) < 0) 
		{
			printf("Failed to register RADIUS authentication handler\n");
			return NULL;
		}
		
		global_rad_ctx = rad_ctx;
	}
	
	return global_rad_ctx;
}

struct radius_client_data *get_rad_client_ctx()
{
	if (global_rad_ctx != NULL) return global_rad_ctx->radius;
	return NULL;
}

int add_eap_ctx_rad_client(struct eap_auth_ctx *eap_ctx)
{
	
	if (global_rad_ctx == NULL){
		 return -1;
	 }
	
	eap_ctx->next=global_rad_ctx->eap_ctx;
	global_rad_ctx->eap_ctx = eap_ctx;

	return 0;
	
}

struct eap_auth_ctx *search_eap_ctx_rad_client(u8 identifier)
{
	pthread_mutex_lock(&radmutex_list);
	struct eap_auth_ctx *searched = global_rad_ctx->eap_ctx;
	
	while (searched != NULL)
	{
		if (searched->radius_identifier == identifier) break; 
		else	
			searched=searched->next;
		
	}
	pthread_mutex_unlock(&radmutex_list);
	return searched;
}


int eap_auth_init(struct eap_auth_ctx *eap_ctx, void *eap_ll_ctx)
{
	pthread_mutex_lock(&radmutex);
	/*if (rad_client_init(&global_rad_ctx) < 0)
		return -1;*/
	
	struct eapol_callbacks *eap_cb;
	eap_cb=os_zalloc(sizeof(*eap_cb));
	
	struct eap_config *eap_conf;
	eap_conf=os_zalloc(sizeof(*eap_conf));
	
	os_memset(eap_ctx, 0, sizeof(*eap_ctx));
	
	if (eap_server_register_methods(&(eap_ctx->eap_methods)) < 0)
	{
		pthread_mutex_unlock(&radmutex);
		return -1;
	}
	
	/*if (eap_auth_init_tls(eap_ctx) < 0)
		return -1;*/
	
	os_memset(eap_cb, 0, sizeof(*eap_cb));
	eap_cb->get_eap_user = server_get_eap_user;
	eap_cb->get_eap_req_id_text = server_get_eap_req_id_text;
	
	os_memset(eap_conf, 0, sizeof(*eap_conf));
	eap_conf->eap_server = 0;
	//eap_conf->backend_auth = 1; /*Rafa: This activates the pass-through mode*/
	eap_conf->backend_auth = 0;
	eap_conf->ssl_ctx = eap_ctx->tls_ctx;
	eap_conf->eap_methods=eap_ctx->eap_methods;
	
	eap_ctx->eap = eap_server_sm_init(eap_ctx, eap_cb, eap_conf);
	if (eap_ctx->eap == NULL){
		pthread_mutex_unlock(&radmutex);
		return -1;
	}
	
	eap_ctx->eap_if = eap_get_interface(eap_ctx->eap);
	
	/* Enable "port" and request EAP to start authentication. */
	eap_ctx->eap_if->portEnabled = TRUE;
	eap_ctx->eap_if->eapRestart = TRUE;
	/*
	 * I should do this only for a single user and single thread
	 */
	//radctx->eap_srv_ctx=eap_ctx;
	eap_ctx->rad_ctx = global_rad_ctx;
	add_eap_ctx_rad_client(eap_ctx);
	//eap_ctx->eap_ll_cb = eap_ll_cb;
	eap_ctx->eap_ll_ctx = eap_ll_ctx;

	pthread_mutex_unlock(&radmutex);
	return 0;
}

void eap_auth_deinit(struct eap_auth_ctx *eap_ctx)
{
	pthread_mutex_lock(&radmutex);
	
	eap_server_sm_deinit(eap_ctx->eap);
	eap_server_unregister_methods(&(eap_ctx->eap_methods));
	tls_deinit(eap_ctx->tls_ctx);
	
	pthread_mutex_unlock(&radmutex);
}

int eap_auth_step(struct eap_auth_ctx* eap_ctx)
{
	pthread_mutex_lock(&radmutex);
	int res = 0;
	//struct eap_server_ctx *eap_ctx = pana_session->eap_srv_ctx;
	
	res = eap_server_sm_step(eap_ctx->eap);
	
	if (eap_ctx->eap_if->aaaEapResp)
	{
		eap_auth_encapsulate_radius(eap_ctx,eap_ctx->eap_if->aaaEapRespData);
		eap_ctx->eap_if->aaaEapResp = FALSE;
	}
		
	
	/*if (eap_ctx->eap_if->eapReq) {
		printf("==> eap_auth_step Request\n");
		process = 1;
		//eap_ctx->eap_if->eapReq = 0;
	}
	
	if (eap_ctx->eap_if->eapSuccess) {
		printf("==> eap_auth_step Success\n");
		process = 1;
		res = 0;
		//eap_ctx->eap_if->eapSuccess = 0;
		
		if (eap_ctx->eap_if->eapKeyAvailable) {
			wpa_hexdump(MSG_DEBUG, "EAP keying material",
						eap_ctx->eap_if->eapKeyData,
						eap_ctx->eap_if->eapKeyDataLen);
		}
	}
	
	if (eap_ctx->eap_if->eapFail) {
		printf("==> eap_auth_step Fail\n");
		process = 1;
		//eap_ctx->eap_if->eapFail = 0;
	}
	
	if (process && eap_ctx->eap_if->eapReqData) {
		res = 1;
	}*/

	pthread_mutex_unlock(&radmutex);
	return res;
}


/*void eap_auth_rx(struct eap_auth_ctx *eap_ctx,const u8 *data, size_t data_len)
{
	wpabuf_free(eap_ctx->eap_if->eapRespData);
	eap_ctx->eap_if->eapRespData = wpabuf_alloc_copy(data, data_len);
	if (eap_ctx->eap_if->eapRespData)
		eap_ctx->eap_if->eapResp = TRUE;
	
	eap_auth_step(eap_ctx);
}*/

void eap_auth_set_eapResp(struct eap_auth_ctx* eap_ctx, Boolean value)
{	
	eap_ctx->eap_if->eapResp = value;
}
void eap_auth_set_eapRespData(struct eap_auth_ctx* eap_ctx, const u8 *eap_packet, size_t eap_packet_len)
{
	wpabuf_free(eap_ctx->eap_if->eapRespData);
	eap_ctx->eap_if->eapRespData = wpabuf_alloc_copy(eap_packet, eap_packet_len);
}

void eap_auth_set_portEnabled(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->portEnabled = value;
}
void eap_auth_set_eapRestart(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->eapRestart = value;
}
void eap_auth_set_retransWhile(struct eap_auth_ctx* eap_ctx, int retransWhile)
{
	eap_ctx->eap_if->retransWhile = retransWhile;
}
void eap_auth_set_eapSRTT(struct eap_auth_ctx* eap_ctx, int eapSRTT)
{
	eap_ctx->eap_if->eapSRTT = eapSRTT;
}
void eap_auth_set_eapRTTVAR(struct eap_auth_ctx* eap_ctx, int eapRTTVAR)
{
	eap_ctx->eap_if->eapRTTVAR = eapRTTVAR;
}

Boolean eap_auth_get_eapReq(struct eap_auth_ctx* eap_ctx)
{
	return eap_ctx->eap_if->eapReq;
}

void eap_auth_set_eapReq(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->eapReq = value;
}

struct wpabuf *eap_auth_get_eapReqData(struct eap_auth_ctx* eap_ctx)
{
	return eap_ctx->eap_if->eapReqData;				
}

Boolean eap_auth_get_eapNoReq(struct eap_auth_ctx* eap_ctx)
{
	return eap_ctx->eap_if->eapNoReq;				
}

void eap_auth_set_eapNoReq(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->eapNoReq = value;
}

Boolean eap_auth_get_eapSuccess(struct eap_auth_ctx* eap_ctx)
{
	return eap_ctx->eap_if->eapSuccess;				
}

void eap_auth_set_eapSuccess(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->eapSuccess = value;
}

Boolean eap_auth_get_eapFail(struct eap_auth_ctx* eap_ctx)
{
	return eap_ctx->eap_if->eapFail;		
}

void eap_auth_set_eapFail(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->eapFail = value;
}

void eap_auth_set_eapTimeout(struct eap_auth_ctx* eap_ctx, Boolean value)
{
	eap_ctx->eap_if->eapTimeout = value;
}

Boolean eap_auth_get_eapTimeout(struct eap_auth_ctx* eap_ctx)
{
	return eap_ctx->eap_if->eapTimeout;	
}

Boolean eap_auth_get_eapKeyAvailable(struct eap_auth_ctx *eap_ctx)
{
	return eap_ctx->eap_if->eapKeyAvailable;
}

u8 *eap_auth_get_eapKeyData(struct eap_auth_ctx *eap_ctx, size_t *key_len)
{
	*key_len = 64;
	return eap_ctx->eap_if->eapKeyData;
}

u8 *eap_auth_get_eapIdentity(struct eap_auth_ctx *eap_ctx, size_t *length)
{
	*length = eap_ctx->eap_identity_len;
	return eap_ctx->eap_identity;
}
