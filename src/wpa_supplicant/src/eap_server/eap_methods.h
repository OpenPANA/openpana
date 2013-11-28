/*
 * EAP server method registration
 * Copyright (c) 2004-2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef EAP_SERVER_METHODS_H
#define EAP_SERVER_METHODS_H

#include "eap_common/eap_defs.h"

const struct eap_method * eap_server_get_eap_method(struct eap_method *eap_methods,int vendor,
						    EapType method);
struct eap_method * eap_server_method_alloc(int version, int vendor,
					    EapType method, const char *name);
void eap_server_method_free(struct eap_method *method);
int eap_server_method_register(struct eap_method **eap_methods,struct eap_method *method);

EapType eap_server_get_type(struct eap_method *eap_methods, const char *name, int *vendor);
void eap_server_unregister_methods(struct eap_method **eap_methods);
const char * eap_server_get_name(struct eap_method *eap_methods, int vendor, EapType type);

/* EAP server method registration calls for statically linked in methods */
int eap_server_identity_register(struct eap_method **eap_methods);
int eap_server_md5_register(struct eap_method **eap_methods);
int eap_server_tls_register(struct eap_method **eap_methods);
int eap_server_mschapv2_register(struct eap_method **eap_methods);
int eap_server_peap_register(struct eap_method **eap_methods);
int eap_server_tlv_register(struct eap_method **eap_methods);
int eap_server_gtc_register(struct eap_method **eap_methods);
int eap_server_ttls_register(struct eap_method **eap_methods);
int eap_server_sim_register(struct eap_method **eap_methods);
int eap_server_aka_register(struct eap_method **eap_methods);
int eap_server_aka_prime_register(struct eap_method **eap_methods);
int eap_server_pax_register(struct eap_method **eap_methods);
int eap_server_psk_register(struct eap_method **eap_methods);
int eap_server_sake_register(struct eap_method **eap_methods);
int eap_server_gpsk_register(struct eap_method **eap_methods);
int eap_server_vendor_test_register(struct eap_method **eap_methods);
int eap_server_fast_register(struct eap_method **eap_methods);
int eap_server_wsc_register(struct eap_method **eap_methods);
int eap_server_ikev2_register(struct eap_method **eap_methods);
int eap_server_tnc_register(struct eap_method **eap_methods);

#endif /* EAP_SERVER_METHODS_H */
