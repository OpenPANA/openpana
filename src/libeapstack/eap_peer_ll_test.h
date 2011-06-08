/*
 *  eap_peer_ll_test.h
 *  
 *
 *  Created by Rafa Marin Lopez on 27/10/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 */

#include "eap_peer_interface.h"

#define PANA_PORT 9000

struct eap_ll_test_ctx
{
	struct eap_peer_ctx eap_ctx;
	struct sockaddr_in eap_ll_dst_addr;
	int addr_size;
	int eap_ll_sock;
	struct eap_ll_test_ctx *next;
};