/*
 *  eap_auth_ll_test.c
 *  
 *
 *  Created by Rafa Marin Lopez on 25/10/10.
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 */

#include "eap_auth_ll_test.h"

#define EAP_LL_PORT 9000
#define RADIUS_PORT 8000


/*struct eap_ll_callbacks eap_ll_cb;
struct eap_ll_test_ctx ll_ctx;*/


int eap_ll_test_st_step(void *ctx)
{
	printf("Llamando a callback\n");
	return -1;
}

int eap_ll_send(u8 *data, int data_len)
{
	/*return = sendto(new_session->sock, data, data_len, 0,
					(struct sockaddr *) &(new_session->dst_addr),
					new_session->addr_size);*/
}

int process_receive_eap_ll_msg(struct eap_ll_test_ctx **eap_ll_ctx_list, int eap_ll_sock,
												   struct sockaddr_in *eap_ll_dst_addr, int addr_size, 
												   u8 *udp_packet, int length)
{
	//struct eap_ll_callbacks *eap_ll_cb=NULL;
	struct eap_ll_test_ctx *ll_ctx=NULL;

	
	if (memcmp(udp_packet,"START_AUTH",10) == 0)
	{
		ll_ctx=os_zalloc(sizeof(*ll_ctx));
		ll_ctx->next=*eap_ll_ctx_list;
		*eap_ll_ctx_list = ll_ctx;
		
		ll_ctx->eap_ll_dst_addr = *eap_ll_dst_addr;
		ll_ctx->addr_size = addr_size;
		ll_ctx->eap_ll_sock = eap_ll_sock;
		
		//eap_ll_cb=os_zalloc(sizeof(*eap_ll_cb));
		//eap_ll_cb->eap_ll_st_step = eap_ll_test_st_step;
		if (eap_auth_init(&(ll_ctx->eap_ctx), ll_ctx) < 0) return;
		eap_auth_step(&(ll_ctx->eap_ctx));
		
		if (eap_auth_get_eapReq(&(ll_ctx->eap_ctx)) == TRUE)
		{
			struct wpabuf *eap_packet=eap_auth_get_eapReqData(&(ll_ctx->eap_ctx));
						
			eap_auth_set_eapReq(&(ll_ctx->eap_ctx), FALSE);
			
			int slen=sendto(ll_ctx->eap_ll_sock, wpabuf_head(eap_packet), wpabuf_len(eap_packet), 0,
							(struct sockaddr *) &(ll_ctx->eap_ll_dst_addr),ll_ctx->addr_size);
			
			if (slen < 0) {printf("RAFA: Error sending\n"); return -1;}
		}
	}
	else
	{
		/*RAFA: We must find a EAP lower layer session in the list of context that matches with the incoming packet*/
		struct eap_ll_test_ctx *eap_ll_ctx = *eap_ll_ctx_list;
		
		eap_auth_set_eapResp(&(eap_ll_ctx->eap_ctx),TRUE);
		eap_auth_set_eapRespData(&(eap_ll_ctx->eap_ctx),udp_packet,length);
		eap_auth_step(&(eap_ll_ctx->eap_ctx));
	}

	return 0;
}

struct eap_ll_test_ctx * process_receive_radius_msg(u8 *udp_packet, int length)
{
	struct radius_msg *radmsg = radius_msg_parse(udp_packet, length);
	struct radius_client_data *radius_data = get_rad_client_ctx();
	int radius_type=RADIUS_AUTH;
	
	struct radius_hdr *hdr = radius_msg_get_hdr(radmsg);
	struct eap_auth_ctx *eap_ctx=search_eap_ctx_rad_client(hdr->identifier);
	struct eap_ll_test_ctx *ll_ctx=NULL;
	
	if (eap_ctx != NULL)
	{
		radius_client_receive(radmsg,radius_data,&radius_type);
		
		if ((eap_auth_get_eapReq(eap_ctx) == TRUE) || (eap_auth_get_eapSuccess(eap_ctx) == TRUE))
		{
			struct wpabuf *eap_packet=eap_auth_get_eapReqData(eap_ctx);
			
			ll_ctx = (struct eap_ll_test_ctx *)eap_ctx->eap_ll_ctx;
			
			int slen=sendto(ll_ctx->eap_ll_sock, wpabuf_head(eap_packet), wpabuf_len(eap_packet), 0,
							(struct sockaddr *) &(ll_ctx->eap_ll_dst_addr),ll_ctx->addr_size);
			
			if (slen < 0) {printf("Error sending\n"); return -1;}
			
			eap_auth_set_eapReq(eap_ctx, FALSE);
			
			if (eap_auth_get_eapKeyAvailable(eap_ctx) == TRUE)
			{
				printf("EAP lower-layer Key Available!!!\n");	
				unsigned int key_len;
				u8* key=eap_auth_get_eapKeyData(&(ll_ctx->eap_ctx), &key_len);
				int i;
				for(i=0; i < key_len; i++)
					printf("%02x",key[i]);
				printf("\n");
				size_t eap_id_len;
				u8* eap_id = eap_auth_get_eapIdentity(&(ll_ctx->eap_ctx), &eap_id_len);
			
				printf("Authenticator User --> ");	
				for(i=0; i < eap_id_len; i++)
					printf("%c",eap_id[i]);
				printf("\n");
				
			}
			
			return ll_ctx;

		}
	} 
	return NULL;
}



int main(int argc, char *argv[])
{
	
	
	int radius_sock;
	int eap_ll_sock;
	struct sockaddr_in sa;
	
	fd_set mreadset;		/*master read set*/
	
	rad_client_init();
	
	
	eap_ll_sock=socket(AF_INET, SOCK_DGRAM, 0);
	memset((char *) &sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(EAP_LL_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    
	if (bind(eap_ll_sock, &sa, sizeof(sa))==-1)
	{
		perror("Binding socket error:\n");
		return;
	}
	
	
	
	
	struct radius_client_data *radius_data = get_rad_client_ctx();
	
	if (radius_data != NULL)
	{
		radius_sock = radius_data->auth_serv_sock;
	}
	
		
	u8 udp_packet[2048];
	struct sockaddr_in eap_ll_dst_addr, radius_dst_addr;
	int addr_size;
	struct eap_ll_test_ctx *eap_ll_ctx_list=NULL, *current_eap_ll_ctx=NULL;
	
	while (1)
	{
		FD_ZERO(&mreadset);
		FD_SET(radius_sock,&mreadset);
		FD_SET(eap_ll_sock,&mreadset);
		int ret = select(eap_ll_sock + 1, &mreadset, NULL, NULL, NULL);
		
		if (ret > 0)
		{
			if (FD_ISSET(eap_ll_sock,&mreadset))
			{
				addr_size = sizeof(eap_ll_dst_addr);
				int length = recvfrom(eap_ll_sock, udp_packet, sizeof(udp_packet), 0, (struct sockaddr *)&(eap_ll_dst_addr), (socklen_t *)&(addr_size)); 
				if (length > 0)
				{
					process_receive_eap_ll_msg(&eap_ll_ctx_list, eap_ll_sock, &eap_ll_dst_addr, addr_size, udp_packet, length);
				} 
				else printf("recvfrom returned ret=%d, errno=%d\n", length, errno);
			}
			
			if (FD_ISSET(radius_sock,&mreadset))
			{
				addr_size = sizeof(radius_dst_addr);				
				int length = recvfrom(radius_sock, udp_packet, sizeof(udp_packet), 0, (struct sockaddr *)&(radius_dst_addr), (socklen_t *)&(addr_size));
				
				if (length > 0)
				{
					process_receive_radius_msg(udp_packet, length);
				} 
				else printf("recvfrom returned ret=%d, errno=%d\n", length, errno);
			}
		}
	}
}