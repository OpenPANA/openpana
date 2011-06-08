/*
 *  eap_peer_ll_test.c
 *  
 *
 *  Created by Rafa Marin Lopez on 27/10/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 */

#include "eap_peer_ll_test.h"

int send_EAP_start(int sock, struct sockaddr_in *auth_sockaddr)
{
	
	char start[11]="START_AUTH";

	return sendto(sock, start, 10, 0,
						(struct sockaddr *)auth_sockaddr,
						sizeof(*auth_sockaddr)) ;
}




main(int argc,char *argv[])
{
	struct sockaddr_in eap_peer_ll_sockaddr, eap_auth_ll_sockaddr;
	int eap_ll_sock;
	
	if ((eap_ll_sock=socket(AF_INET, SOCK_DGRAM, 0))==-1)
	{
		perror("socket");
		return -1;
	}
	
	memset((char *) &eap_peer_ll_sockaddr, 0, sizeof(eap_peer_ll_sockaddr));
    eap_peer_ll_sockaddr.sin_family = AF_INET;
    eap_peer_ll_sockaddr.sin_port = htons(0);
    eap_peer_ll_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
    if (bind(eap_ll_sock, &eap_peer_ll_sockaddr, sizeof(eap_peer_ll_sockaddr))==-1)
	{
		perror("socket");
		return -1;
	}
	
	eap_auth_ll_sockaddr.sin_family = AF_INET;
	eap_auth_ll_sockaddr.sin_port = htons(PANA_PORT);
	inet_pton(AF_INET,"127.0.0.1", &eap_auth_ll_sockaddr.sin_addr);
	
	struct eap_ll_test_ctx *eap_peer_ll_ctx = os_malloc(sizeof(struct eap_ll_test_ctx));
	
	eap_peer_init(&(eap_peer_ll_ctx->eap_ctx),eap_peer_ll_ctx);
	send_EAP_start(eap_ll_sock,&eap_auth_ll_sockaddr);
	
	while (1)
	{
		struct sockaddr_in eap_auth_ll_addr; 
		int addr_size = sizeof(eap_auth_ll_addr);
		u8 eap_packet[2048];
	
		int length = recvfrom(eap_ll_sock, eap_packet, sizeof(eap_packet), 0, (struct sockaddr *)&eap_auth_ll_addr, (socklen_t *)&addr_size);
		
		if (length > 0)
		{			
			eap_peer_set_eapReq(&(eap_peer_ll_ctx->eap_ctx), TRUE);
			eap_peer_set_eapReqData(&(eap_peer_ll_ctx->eap_ctx), eap_packet, length);
			eap_peer_step(&(eap_peer_ll_ctx->eap_ctx));
			
			if (eap_peer_get_eapResp(&(eap_peer_ll_ctx->eap_ctx)) == TRUE)
			{
				struct wpabuf *eap_resp = eap_peer_get_eapRespData(&(eap_peer_ll_ctx->eap_ctx));
				eap_peer_set_eapResp(&(eap_peer_ll_ctx->eap_ctx), FALSE);

				int ret= sendto(eap_ll_sock, wpabuf_head(eap_resp), wpabuf_len(eap_resp), 0,
					   (struct sockaddr *)&eap_auth_ll_addr,
					   sizeof(eap_auth_ll_addr));				
			}
			else if (eap_peer_get_eapSuccess(&(eap_peer_ll_ctx->eap_ctx)) == TRUE)
			{
				printf("EAP lower-layer SUCCESS!!!\n");	
				if (eap_peer_get_eapKeyAvailable(&(eap_peer_ll_ctx->eap_ctx)) == TRUE)
				{
					printf("RAFA: EAP lower-layer Key Available!!!\n");	
					unsigned int key_len;
					u8* key=eap_peer_get_eapKeyData(&(eap_peer_ll_ctx->eap_ctx), &key_len);
					int i;
					for(i=0; i < key_len; i++)
						printf("%02x",key[i]);
					printf("\n");
				}
			}
			else if (eap_peer_get_eapFail(&(eap_peer_ll_ctx->eap_ctx)) == TRUE)
			{
				printf("EAP lower-layer FAIL!!!\n");	
			}
		}
		
		
	}
	
}
