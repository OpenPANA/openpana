/**
 * @file mainserver.c
 * @brief  PAA's main program.
 **/
/*
 *  Created by Rafa Marin Lopez
 *  Copyright 2010 Universidad de Murcia. All rights reserved.
 *
 * 	Modified by Pedro Moreno Sánchez and Francisco Vidal Meca on 16/11/10.
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
 *  
 *  https://sourceforge.net/projects/openpana/
 */

#include "mainserver.h"

#include "state_machines/statemachine.h"
#include "state_machines/paamachine.h"
#include "state_machines/session.h"
#include "panamessages.h"
#include "state_machines/paamachine.h"
#include "panautils.h"
#include "lalarm.h"
#include "prf_plus.h"

/** Reqs for performance test maybe included somewhere else */
#include <sys/time.h>
/** end performance includes*/

//Global variables
static bool fin = FALSE;

/** Keeps the last key-id assigned by the server. The first one is random
 * generated and the following will be the result of increasing the 
 * current global_key_id. */
char * global_key_id;

/** Linked list of server's PANA sessions.*/
struct pana_ctx_list* list_pana_sessions = NULL;
/** Mutex associated to PANA sessions' list.*/
pthread_mutex_t list_sessions_mutex;

/** Linked list of server's tasks.*/
struct task_list* list_tasks = NULL;
/** Last task. */
struct task_list* last_task = NULL;
/** Mutex associated to tasks' list. */
pthread_mutex_t list_tasks_mutex;

/** Alarm's list. */
struct lalarm* list_alarms = NULL;

/** Semaphore used to wait for new tasks by workers. */
sem_t got_task; 

void signal_handler(int sig) {
    printf("\nStopping server, signal: %d\n", sig);
    fin = 1;
}

void print_list_alarms(){
	#ifdef DEBUG
    struct lalarm* ptr = list_alarms;
	
	while (ptr != NULL) {
		pana_debug("Showing session alarm id: %#X", ptr->pana_session->session_id);
		pana_debug("Showing alarm type: %#X", ptr->id);
		ptr = ptr->sig;
	}
	#endif
}


void print_list_sessions(){
	#ifdef DEBUG
    struct pana_ctx_list* ptr = list_pana_sessions;
    // lock the mutex, to assure exclusive access to the list
    pthread_mutex_lock(&list_sessions_mutex);

	while (ptr != NULL) {
		pana_debug("Showing session id: %#X", ptr->pana_session->session_id);
		ptr = ptr->next;
	}
    
    // unlock mutex
    pthread_mutex_unlock(&list_sessions_mutex);
    #endif
}

void * process_receive_eap_ll_msg(void *arg) {
    struct pana_func_parameter * pana_params = (struct pana_func_parameter*) arg;

    // Current pana session.
    pana_ctx * pana_session;
    pana * msg = pana_params->pana_msg;
	struct sockaddr_in pre_dst_addr;
	struct sockaddr_in6 pre_dst_addr6;

	//Init the PRE address (for IPv4 and IPv6)
    memset(&pre_dst_addr, 0, sizeof(pre_dst_addr));
    memset(&pre_dst_addr6, 0, sizeof(pre_dst_addr6));

    //If the message is a PRY
	if (ntohs(msg->msg_type) == PRY_MSG){
		char * elmnt;
		
		/////Get the PRE address information and get the PaC address information
		if (IP_VERSION==4){
			
			pre_dst_addr.sin_family= AF_INET;
			memcpy (&(pre_dst_addr.sin_addr), &(pana_params->eap_ll_dst_addr->sin_addr), sizeof(struct in_addr));
			pre_dst_addr.sin_port = pana_params->eap_ll_dst_addr->sin_port;

			//Restore the PaC Information as param
			elmnt = getAvp(pana_params->pana_msg, PACINFORMATION_AVP);
			memcpy (&(pana_params->eap_ll_dst_addr->sin_addr), (elmnt+sizeof(avp_pana)), sizeof (struct in_addr));
			memcpy (&(pana_params->eap_ll_dst_addr->sin_port), (elmnt+sizeof(avp_pana)+sizeof(struct in_addr)), sizeof(short));
		}
		else if (IP_VERSION ==6){
			
			pre_dst_addr6.sin6_family= AF_INET6;
			memcpy (&(pre_dst_addr6.sin6_addr), &(pana_params->eap_ll_dst_addr6->sin6_addr), sizeof(struct in6_addr));
			pre_dst_addr6.sin6_port = pana_params->eap_ll_dst_addr6->sin6_port;

			//Restore the PaC Information as param
			elmnt = getAvp(pana_params->pana_msg, PACINFORMATION_AVP);
			memcpy (&(pana_params->eap_ll_dst_addr6->sin6_addr), (elmnt+sizeof(avp_pana)), sizeof (struct in6_addr));
			memcpy (&(pana_params->eap_ll_dst_addr6->sin6_port), (elmnt+sizeof(avp_pana)+sizeof(struct in6_addr)), sizeof(short));
		}

		//Restore the message sent by the PaC from the RelayedMessage AVP
		msg = (pana*) (getAvp(pana_params->pana_msg, RELAYEDMESSAGE_AVP)+sizeof(avp_pana));
	}

    if (ntohs(msg->msg_type) == PCI_MSG) {//If a PCI message is received

		// A session is created to make a transition but it's not saved. It tries to avoid
		// attacks from clients (PCI flood).
        pana_session = XMALLOC(pana_ctx,1);
        initSession(pana_session); 

		//If a PRY message has been received, the PRE destination address must have been updated
		if(IP_VERSION==4 && pre_dst_addr.sin_family!=0){
			memcpy(&(pana_session->pre_dst_addr),  &(pre_dst_addr), sizeof(struct sockaddr_in));
		}
		else if (IP_VERSION==6 && pre_dst_addr6.sin6_family!=0) {
			memcpy(&(pana_session->pre_dst_addr6),  &(pre_dst_addr6), sizeof(struct sockaddr_in6));
		}

        //Update variables depends on server
        uint16_t port;
        char * ip;
        char ip6 [INET6_ADDRSTRLEN];
        if (IP_VERSION==4){
			port = ntohs(pana_params->eap_ll_dst_addr->sin_port);
			ip = inet_ntoa(pana_params->eap_ll_dst_addr->sin_addr);
			pana_session->session_id = generateSessionId(ip, port);
		}
		else if (IP_VERSION==6){
			port = ntohs(pana_params->eap_ll_dst_addr6->sin6_port);
			inet_ntop(AF_INET6, &(pana_params->eap_ll_dst_addr6->sin6_addr),ip6, INET6_ADDRSTRLEN);
			pana_session->session_id = generateSessionId(ip6, port);
		}
   
        pana_session->socket = pana_params->sock;
        if (IP_VERSION==4)
			pana_session->eap_ll_dst_addr = *(pana_params->eap_ll_dst_addr);
		else if (IP_VERSION==6)
			pana_session->eap_ll_dst_addr6 = *(pana_params->eap_ll_dst_addr6);
		pana_session->server_ctx.global_key_id = global_key_id;
        
        pana_session->list_of_alarms = &(list_alarms);

        //FIXME: Debería comprobarse que pasa cuando un cliente "muere" y ese mismo vuelve a lanzar un PCI
        //Ataque por PCIs falsos para borrar sesiones? reautenticación?
        //Delete the previous session if it exists in the session list and the alarm list
        remove_session(pana_session->session_id);
        remove_alarm(&(list_alarms), pana_session->session_id);
       
        //Add the provisional session in the alarm list
        add_alarma(&(list_alarms), pana_session, TIME_PCI, PCI_ALARM);
        

    }
    else if ((ntohs(msg->msg_type) == PAUTH_MSG) && // If it is the first authentication message
            ((ntohs(msg->flags) & S_FLAG) == S_FLAG)) {// it is created a new session for the new client
       
        //Generate the session id asociated to client's port and ip
        uint16_t port;
        char * ip;
        uint32_t session_id;
        char ip6 [INET6_ADDRSTRLEN];
        
        if (IP_VERSION==4){
			port = ntohs(pana_params->eap_ll_dst_addr->sin_port);
			ip = inet_ntoa(pana_params->eap_ll_dst_addr->sin_addr);
			session_id = generateSessionId(ip, port);
		}
		else if (IP_VERSION==6){
			port = ntohs(pana_params->eap_ll_dst_addr6->sin6_port);
			inet_ntop(AF_INET6, &(pana_params->eap_ll_dst_addr6->sin6_addr),ip6, INET6_ADDRSTRLEN);
			session_id = generateSessionId(ip6, port);
		}
        
        pana_session = get_alarm_session(&(list_alarms), session_id, PCI_ALARM);
        
        if (pana_session == NULL) {
			pana_warning("There isn't a PCI session corresponding with this answer");
            return NULL;
        }
        pana_session->list_of_alarms = &(list_alarms);
        
        add_session(pana_session);
        pana_debug("Session-Id added to the list is: %d", session_id);
    } 
    
    else { //If the messsage is another one
        uint32_t id = ntohl(msg->session_id);
        pana_debug("It's gonna search id: %d", id);
        // Get the session from the PANA sessions' list.
        pana_session = get_session(id);
        
        if (pana_session == NULL) { //If the session doesn't exist
			pana_error("Tried to send a message from an unauthenticated client");
            return 0;
        }

    }
    
	pthread_mutex_lock(&(pana_session->mutex));
        struct timespec ti, tf, differ;
	double timestamp;
        //Get time measurement for the initial time
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ti);

    //Use the correct session
    updateSession((char *)msg, pana_session);
    transition(pana_session);

        //Get time for the final time
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tf);
        
        differ = diff(ti,tf);
        fprintf(stderr,"time in microseconds\n");
	timestamp= differ.tv_sec*1000000 + differ.tv_nsec/1000.0;
	fprintf(stderr, "%g\n", timestamp);

        //Get time measurement for the initial time
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ti);

    check_eap_status(pana_session);
        //Get time for the final time
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tf);
        
        differ = diff(ti,tf);
        fprintf(stderr,"time in microseconds\n");
	timestamp= differ.tv_sec*1000000 + differ.tv_nsec/1000.0;
	fprintf(stderr, "%g\n", timestamp);

	if (current_session->CURRENT_STATE == OPEN){
		//////////// ACCESS PHASE ////////////

		if (NUMBER_PING_AUX){
			if (NUMBER_PING_AUX){
				NUMBER_PING_AUX = NUMBER_PING_AUX-1;
				add_alarma(&list_alarms, pana_session, PING_TIME, PING_ALARM);
			}
		} else{ // Reset the number of ping messages to be exchanged when the
				// next access phase is reached.
			NUMBER_PING_AUX = NUMBER_PING;
		}
	}

	// When a session is closed, its correspondending memory must be removed.    
    if (pana_session->CURRENT_STATE == CLOSED) {
        remove_alarm(&list_alarms, pana_session->session_id); //Remove the alarms
        remove_session(pana_session->session_id); //Remove the session
        pthread_mutex_unlock(&(pana_session->mutex));
        return 0;
    }
    pana_debug("PANA message treatment finished");
	pthread_mutex_unlock(&(pana_session->mutex));
    return 0;
}




void* process_receive_radius_msg(void* arg) {
    struct radius_func_parameter radius_params = *((struct radius_func_parameter*) arg);

    int radius_type = RADIUS_AUTH;

    //Get the function's parameters.
    struct radius_msg *radmsg = radius_params.msg;

    // Get the information about the new message received
    struct radius_client_data *radius_data = get_rad_client_ctx();
    struct radius_hdr *hdr = radius_msg_get_hdr(radmsg);
	struct eap_auth_ctx *eap_ctx = search_eap_ctx_rad_client(hdr->identifier);

    if (eap_ctx == NULL){
		pana_error("eap_ctx NULL. It can't be used");
		return NULL;
	}
	
    pana_ctx * ll_session = (pana_ctx*) (eap_ctx->eap_ll_ctx);
    pthread_mutex_lock(&(ll_session->mutex));

    //Delete the alarm associated to this message
    pana_debug("Getting an alarm session in radius function with id: %d\n", ll_session->session_id);
    pana_debug("Generating new session id with ip: %s and port: %d\n", inet_ntoa(ll_session->eap_ll_dst_addr.sin_addr), ntohs(ll_session->eap_ll_dst_addr.sin_port));
	get_alarm_session(ll_session->list_of_alarms, ll_session->session_id, RETR_AAA);
	
    if (eap_ctx != NULL) {
		
        radius_client_receive(radmsg, radius_data, &radius_type);

		// In case of a EAP Fail is produced.
        if ((eap_auth_get_eapFail(eap_ctx) == TRUE)){
			pana_debug("There's an eap fail in RADIUS");
			transition((pana_ctx *) eap_ctx->eap_ll_ctx);
		}
		
        else if ((eap_auth_get_eapReq(eap_ctx) == TRUE)
                || (eap_auth_get_eapSuccess(eap_ctx) == TRUE)) {
					
			pana_debug("There's an eap request in RADIUS");
			pana_debug("Trying to make a transition with the message from RADIUS");
            transition((pana_ctx *) eap_ctx->eap_ll_ctx);
            pthread_mutex_unlock(&(ll_session->mutex));
            return NULL;
        }
        else
			pana_debug("There is not eap information in the last received RADIUS message");
    }
    pthread_mutex_unlock(&(ll_session->mutex));
    return NULL;
}

void add_task(task_function funcion, void * arg) {

	int rc; // return code of pthreads functions.
    // lock the mutex, to assure exclusive access to the list
    rc = pthread_mutex_lock(&list_tasks_mutex);
    
    struct task_list * new_element; // A new element in the list

    // create structure with new element
    new_element = XMALLOC(struct task_list,1);
    
    new_element->use_function = funcion;
    new_element->data = arg;
    new_element->next = NULL;


    /* add new session to the end of the list, updating list */
    /* pointers as required */
    if (list_tasks == NULL) { /* special case - list is empty */
        list_tasks = new_element;
        last_task = new_element;
    }
    else {
        last_task->next = new_element;
        last_task = last_task->next;
    }

	pana_debug("add_task: added task");	
    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_tasks_mutex);
    /* signal the condition variable - there's a new task to handle */
    rc = sem_post(&got_task);
}

void add_session(pana_ctx * session) {
    int rc; /* return code of pthreads functions.  */

    struct pana_ctx_list * new_element;

    /* create structure with new request */
    new_element = XMALLOC(struct pana_ctx_list,1);
    new_element->pana_session = session;
    new_element->next = NULL;

    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(&list_sessions_mutex);

    /* add new session to the end of the list, updating list */
    /* pointers as required */
    if (list_pana_sessions == NULL) { /* special case - list is empty */
        list_pana_sessions = new_element;
    } 
    else {
//		struct pana_ctx_list* ptr = new_element;
        new_element->next = list_pana_sessions;
        list_pana_sessions = new_element;
    }

	pana_debug("add_session: added session: %#X",new_element->pana_session->session_id);
    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_sessions_mutex);

}

pana_ctx* get_session(uint32_t id) {
    int rc; /* return code of pthreads functions.  */

    struct pana_ctx_list* session = NULL;

	pana_debug("Trying to get session of id: %d", id);
    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(&list_sessions_mutex);

    if (list_pana_sessions != NULL) {
        session = list_pana_sessions;
        while (session != NULL) {
			pana_debug("Checking id: %d", session->pana_session->session_id);
            if (session->pana_session->session_id == id) break;
            session = session->next;
        }
    }
    
    
    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_sessions_mutex);

    /* return the session to the caller. */
    if (session == NULL) {
		pana_debug("Session not found, id: %d", id);
        return NULL;
    }
    return session->pana_session;
}

void remove_session(uint32_t id) {
    int rc;
    
    struct pana_ctx_list* session = NULL;
    struct pana_ctx_list* anterior = NULL;
    
    pana_debug("Trying to delete session with id: %d", id);
    // lock the mutex, to assure exclusive access to the list 
    rc = pthread_mutex_lock(&list_sessions_mutex);

    if (list_pana_sessions != NULL) {
        session = list_pana_sessions;
        //If the session is the first
        if (session->pana_session->session_id == id) {
			pana_debug("Found and deleted session with id: %d", id);
            list_pana_sessions = list_pana_sessions->next;
            session->next=NULL;
            //XFREE(session); //fixme: Cuidado al poner este free. Hay que verlo con el de remove_alarm (lalarm.c)
            rc = pthread_mutex_unlock(&list_sessions_mutex);
            return;
        }
        session = list_pana_sessions->next;
        anterior = list_pana_sessions;
        while (session != NULL) {
            if (session->pana_session->session_id == id) {
                anterior->next = session->next;
                session->next = NULL;
                //XFREE(session); //fixme: Cuidado al poner este free. Hay que verlo con el de remove_alarm (lalarm.c)
                break;
            }
            anterior = anterior->next;
            session = session->next;
        }
    }

    // unlock mutex 
    rc = pthread_mutex_unlock(&list_sessions_mutex);

}

struct task_list* get_task() {
    int rc; /* return code of pthreads functions.  */
    
    struct task_list* task = NULL;
    
    pana_debug("Trying to get a task.");
    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(&list_tasks_mutex);

    if (list_tasks != NULL) {
        task = list_tasks; 
        list_tasks = list_tasks->next;
        task->next = NULL;
    }


    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_tasks_mutex);

    /* return the task to the caller. */
    if (task == NULL) {
		pana_debug("Task not found");
        return NULL;
    }

    return task;
}

void* handle_worker(void* data) {
    int thread_id = *((int*) data); /* thread identifying number */
    int rc; /* return code of pthreads functions.  */
    struct task_list* a_task = NULL; /* pointer to a task. */
    
    pana_debug("thread '%d' as worker manager", thread_id);
    pana_debug("Starting thread '%d'", thread_id);

    /* lock the mutex, to access the requests list exclusively. */
    sem_wait(&got_task);

    /* do forever.... */
    while (!fin) {
		pana_debug("thread '%d' tries to get a task", thread_id);
        if (list_tasks != NULL) { /* a request is pending */
            a_task = get_task();
        }

        if (a_task) {

            a_task->use_function(a_task->data);

			//FIXME: PEDRO: Habría que liberar esta memoria. El problema está en que
			//cuando la session llega al estado CLOSED, se libera su memoria, y al 
			//intentar liberar la memoria de la tarea, intenta liberar la memoria 
			//de esa session y explota.
			//XFREE(a_task); // Free task's memory
            //Unlock the mutex of this session
            //pthread_mutex_unlock(mutex);
        }
        rc = sem_wait(&got_task);
        /* and after we return from pthread_cond_wait, the mutex  */
        /* is locked again, so we don't need to lock it ourselves */
    }
	return NULL;
}

void* handle_network_management() {
    
    //To handle exit signals
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    
    int radius_sock=0; //Init it to a non-valid value
    int eap_ll_sock=0;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    fd_set mreadset; /*master read set*/

    rad_client_init(AS_IP, AS_PORT, AS_SECRET);

	if (IP_VERSION==4)
		eap_ll_sock = socket(AF_INET, SOCK_DGRAM, 0);
	else if (IP_VERSION==6)
		eap_ll_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    int b = 1;
    // SO_REUSEADDR option is used in case of an unexpected exit, the
    // client will be able to reuse the socket
    if (setsockopt(eap_ll_sock, SOL_SOCKET, SO_REUSEADDR, &b, 4)) {
        perror("setsockopt");
        return 0;
    }

    /*FIXME: Para habilitar los inicios de sesión por parte del servidor
     * habría que escuchar en el puerto del servidor (ahora mismo PANAPORT)
     * y aparte en el PANAPORT, de ésta forma el servidor siempre estará
     * pendiente de posibles PCIs (panaport) y podrá iniciar sesiones
     * en su puerto sin que éste tenga que ser el puerto PANA */
    
    if (IP_VERSION==4){
		memset((char *) & sa, 0, sizeof (sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(SRCPORT);
		sa.sin_addr.s_addr = htonl(INADDR_ANY);
		//Avoid's a warning, bind expects the "const ptr" type
		const struct sockaddr * sockaddr = (struct sockaddr *) & sa;
		if (bind(eap_ll_sock, sockaddr, sizeof (sa)) == -1) {
			perror("Binding socket error:\n");
			return NULL;
		}
	}
	else if (IP_VERSION==6){
		memset((char *) & sa6, 0, sizeof (sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = htons(SRCPORT);
		sa6.sin6_addr = in6addr_any;
		//Avoid's a warning, bind expects the "const ptr" type
		const struct sockaddr * sockaddr = (struct sockaddr *) & sa6;
		if (bind(eap_ll_sock, sockaddr, sizeof (sa6)) == -1) {
			perror("Binding socket error:\n");
			return NULL;
		}
	}

    struct radius_client_data *radius_data = get_rad_client_ctx();

    if (radius_data != NULL) {
		if (IP_VERSION_AUTH==4)
			radius_sock = radius_data->auth_serv_sock;
		else if (IP_VERSION_AUTH==6)
			radius_sock = radius_data->auth_serv_sock6;
    }

    u8 udp_packet[MAX_DATA_LEN];
    struct sockaddr_in eap_ll_dst_addr, radius_dst_addr;
    struct sockaddr_in6 eap_ll_dst_addr6, radius_dst_addr6; //For ipv6 support
    int addr_size;
    
    struct pana_func_parameter *pana_params;
    struct radius_func_parameter *radius_params;
    pana *msg;
    int length;

    while (!fin) {
        FD_ZERO(&mreadset);
        FD_SET(radius_sock, &mreadset);
        FD_SET(eap_ll_sock, &mreadset);
        int ret = select(eap_ll_sock + 1, &mreadset, NULL, NULL, NULL);

        if (ret > 0) {
            //Check pana messages
            if (FD_ISSET(eap_ll_sock, &mreadset)) {
				if (IP_VERSION==4) {
					addr_size = sizeof (eap_ll_dst_addr);
					length = recvfrom(eap_ll_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(eap_ll_dst_addr), (socklen_t *)&(addr_size));
				}
				else if (IP_VERSION==6){
					addr_size = sizeof (eap_ll_dst_addr6);
					length = recvfrom(eap_ll_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(eap_ll_dst_addr6), (socklen_t *)&(addr_size));
				}
                if (length > 0) {
                    //FIXME: Cuándo se libera esto
                    msg = XCALLOC(char,length);
                    memcpy(msg,udp_packet,length);
                    //The message will be checked later when the session
                    //is updated
                    //Init the pana function parameters
                    //FIXME: Cuándo se libera esto
                    pana_params = XCALLOC(struct pana_func_parameter,1);
                    pana_params->pana_msg = msg;
                    if (IP_VERSION==4){
						pana_params->eap_ll_dst_addr = XMALLOC (struct sockaddr_in,1);
						memcpy(pana_params->eap_ll_dst_addr, &(eap_ll_dst_addr), sizeof(struct sockaddr_in));
					}
					else if (IP_VERSION==6){
						pana_params->eap_ll_dst_addr6 = XMALLOC (struct sockaddr_in6,1);
						memcpy(pana_params->eap_ll_dst_addr6, &(eap_ll_dst_addr6), sizeof(struct sockaddr_in6));
					}
                    pana_params->sock = eap_ll_sock;
					pana_params->id_alarm = -1;
                    add_task(process_receive_eap_ll_msg, pana_params/*, ntohl(msg->session_id)*/);
                    
                } else pana_error("recvfrom returned ret=%d, errno=%d", length, errno);
            }
            //Check radius messages
            if (FD_ISSET(radius_sock, &mreadset)) {
				if (IP_VERSION==4){
					addr_size = sizeof (radius_dst_addr);
					length = recvfrom(radius_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(radius_dst_addr), (socklen_t *)&(addr_size));
				}
				else if (IP_VERSION==6){
					addr_size = sizeof (radius_dst_addr6);
					length = recvfrom(radius_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(radius_dst_addr6), (socklen_t *)&(addr_size));
				}

                if (length > 0) {

					radius_params = XCALLOC(struct radius_func_parameter,1);
                    struct radius_msg *radmsg = radius_msg_parse(udp_packet, length);
                    radius_params->msg = XMALLOC (char,length);
                    memcpy(radius_params->msg, radmsg, length);
                    
                    add_task(process_receive_radius_msg, radius_params);
                    
                }
                else
					pana_error("recvfrom returned ret=%d, errno=%d", length, errno);
            }
        }
    }
	return NULL;
}

void* handle_alarm_management() {

    while (TRUE){ // Do it while the PAA is activated.
    
		struct retr_func_parameter retrans_params;

		// Get the actual timestamp.
		double time = getTime();
		
		struct lalarm* alarm = NULL;
		while ((alarm=get_next_alarm(&list_alarms, time)) != NULL){ //Look for the activated alarms.
			 retrans_params.session = (pana_ctx *)alarm->pana_session;
			 retrans_params.id = 0;
			 if (alarm->id == PCI_ALARM) { // A PCI alarm is activated.
				pana_debug("A PCI alarm ocurred");
			}
			else if (alarm->id == RETR_ALARM) { // A PANA retransmission alarm is activated.
				pana_debug("A PANA_RETRANSMISSION alarm ocurred");
				retrans_params.id = RETR_ALARM;				
				add_task(process_retr, &retrans_params);
			}
			else if (alarm->id == SESS_ALARM) {// A session alarm is activated.
				pana_debug("A SESSION alarm ocurred");
				retrans_params.id = SESS_ALARM;
				add_task(process_retr, &retrans_params);
			}
			else if (alarm->id == RETR_AAA) { // An AAA retransmission alarm is activated.
				pana_debug("An AAA_RETRANSMISSION alarm ocurred");
				retrans_params.id = RETR_AAA;
				add_task(process_retr, &retrans_params);
			}
			else if (alarm->id == PING_ALARM) {
				pana_debug("A PING alarm ocurred");
				retrans_params.id = PING_ALARM;
				add_task(process_retr, &retrans_params);
			}
			else { // An unknown alarm is activated.
				pana_debug("An UNKNOWN alarm ocurred");
			}
		}
		waitusec(TIME_WAKE_UP);
	}
	return NULL;
}


void* process_retr(void *arg){
	struct retr_func_parameter* retr_params;

	// Get the function's parameters.
	retr_params = (struct retr_func_parameter*) arg;
	int alarm_id = retr_params->id;
	pana_ctx * pana_session = retr_params->session;

	// Depends on the alarm produced, it is processed.
	if (alarm_id == PCI_ALARM) {
		pana_debug("A PCI alarm ocurred");
	} else if (alarm_id == RETR_ALARM) {
		pana_debug("A PANA_RETRANSMISSION alarm ocurred");
		pthread_mutex_lock(&(pana_session->mutex));
		pana_session->RTX_TIMEOUT = 1; 
		transition(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
		
	} else if (alarm_id == SESS_ALARM) {
		pana_debug("A SESSION alarm ocurred");		
		pthread_mutex_lock(&(pana_session->mutex));
		pana_session->SESS_TIMEOUT = 1; 
		transition(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
		
	} else if (alarm_id == RETR_AAA) {
		pana_debug("An AAA_RETRANSMISSION alarm ocurred");
		pthread_mutex_lock(&(pana_session->mutex));
		retransmitAAA(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
	} else if (alarm_id == PING_ALARM) {
		pana_debug("A PING alarm ocurred");
		pthread_mutex_lock(&(pana_session->mutex));
		pana_session->PANA_PING = 1;
		transition(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
	}
	else {
		pana_debug("An UNKNOWN alarm ocurred");
	}
	return NULL;
}

int main(int argc, char* argv[]) {

    // Variables needed to use threads
    int num_threads = NUM_WORKERS +1; // Workers & network manager
    int i; //loop counter
    int thr_id[num_threads]; // thread IDs
    pthread_t p_threads[num_threads]; // thread's structures

	printf("\n%s Server - %s",PACKAGE_NAME,PACKAGE_VERSION);
	printf("\n%s\n\n",PACKAGE_URL);
    printf("Copyright (C) 2011  Pedro Moreno Sánchez and Francisco Vidal Meca\n");
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions, see COPYING for details.\n\n");

	//Calculates a random value as global key_id value
	generateRandomKeyID(&global_key_id);

    // Init the paa state machine
    pana_ctx * current_pana_ctx = NULL;
    pana_ctx pana_session;
    current_pana_ctx = &pana_session;

    //Pana is initialized
    initSession(current_pana_ctx); 
    initPaaTable(current_pana_ctx);

    //Init got_task semaphore
    sem_init(&got_task, 0, 0);

    //Init the lockers
    pthread_mutex_init(&list_sessions_mutex, NULL);
    pthread_mutex_init(&list_tasks_mutex, NULL);


    //Init global variables
    list_alarms = init_alarms();

    /* create the request-handling threads */
    for (i = 0; i < NUM_WORKERS; i++) {
        thr_id[i] = i;
        pthread_create(&p_threads[i], NULL, handle_worker, (void*) &thr_id[i]);
        pthread_detach(p_threads[i]);
    }
    
    //Create alarm manager thread
    i+=1;
    thr_id[i] = i;
    pthread_create(&p_threads[i], NULL, handle_alarm_management, NULL);
	
	//Once the workers are executed, the network manager function starts
	handle_network_management();
    printf("PANA: The server has stopped.\n");

// TODO : Before ending:
// - Send PTR to all clients if needed
// - Free al memory allocated
	XFREE(global_key_id);
	
	//Free possible remaining alarms
	pana_debug("Going to free alarms");
	/*pthread_mutex_lock(&alarm_list_mutex);
	struct lalarm * alarm_actual = list_alarms;
	while(alarm_actual != NULL){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Freeing alarm: %d.\n",alarm_actual->id);
		#endif
		struct lalarm * last = alarm_actual;
		alarm_actual = last->sig;
		XFREE(last);
	}
	pthread_mutex_unlock(&alarm_list_mutex);*/
	
	//Free remaining tasks
	pana_debug("Going to free tasks");
	/*list_tasks_mutex;
	pthread_mutex_lock(&list_tasks_mutex);
	struct task_list * actual = list_alarms;
	while(actual != NULL){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Freeing task of session: %d.\n",actual->id_session);
		#endif
		struct task_list * last = actual;
		actual = last->next;
		//XFREE(last);
	}
	pthread_mutex_unlock(&list_tasks_mutex);*/
	
	//Free PANA sessions
	pana_debug("Going to free sessions");
	pthread_mutex_lock(&list_sessions_mutex);
	struct pana_ctx_list * ses_actual = list_pana_sessions;
	while ( ses_actual != NULL ){
		pana_debug("Freeing session: %d",ses_actual->pana_session->session_id);
		XFREE(ses_actual->pana_session->key_id);
		XFREE(ses_actual->pana_session->retr_msg);
		XFREE(ses_actual->pana_session->I_PAR);
		XFREE(ses_actual->pana_session->I_PAN);
		XFREE(ses_actual->pana_session->PaC_nonce);
		XFREE(ses_actual->pana_session->PAA_nonce);
		XFREE(ses_actual->pana_session->msk_key);
		/* char *LAST_MESSAGE;*/
		
		eap_auth_deinit(&(ses_actual->pana_session->eap_ctx));
		struct pana_ctx_list * last = ses_actual;
		ses_actual = last->next;
		XFREE(last);
	}
	pthread_mutex_unlock(&list_sessions_mutex);
	
    return 0;
}

void check_eap_status(pana_ctx *pana_session) {
    //Check if exists a new EAP event.
    pana_debug("Starting to check EAP status (check_eap_status)");
    if (eap_auth_get_eapReq(&(pana_session->eap_ctx)) == TRUE) {
		pana_debug("There's an EAPRequest");
        transition(pana_session);
    }

    if (eap_auth_get_eapSuccess(&(pana_session->eap_ctx)) == TRUE) {
		pana_debug("There's an EAPSUCESS");
        transition(pana_session);
    }
    //FIXME: Is it necessary to check the EAP NO Request and EAP Timeout every time?
    if (eap_auth_get_eapNoReq(&(pana_session->eap_ctx)) == TRUE) {
		pana_debug("There's an EAP NO REQUEST");
        //transition(pana_session);
    }
    if (eap_auth_get_eapTimeout(&(pana_session->eap_ctx)) == TRUE) {
		pana_debug("There's an EAP TIMEOUT");
        //transition(pana_session);
    }
    //It is not necessary to check the availability of the key every time
    /*if (eap_auth_get_eapKeyAvailable(&(pana_session->eap_ctx)) == TRUE) {
		pana_debug("There's an EAP KEY AVAILABLE");
        transition(pana_session);
    }*/
    if (eap_auth_get_eapFail(&(pana_session->eap_ctx)) == TRUE) {
		pana_debug("There's an EAP FAIL");
        transition(pana_session);
    }
    pana_debug("Finished EAP check");
}


void retransmitAAA (pana_ctx* current_session){
	// Get the eap ctx associated to current PANA session
	struct eap_auth_ctx * eap_ctx = (struct eap_auth_ctx*) &(current_session->eap_ctx);
#ifdef ISSERVER
	// Add a new retransmission to the counter.
	current_session->server_ctx.RTX_COUNTER_AAA +=1;
	if (current_session->server_ctx.RTX_COUNTER_AAA == MAX_RETR_AAA){ // If the max number of retransmission is reached.
		eap_auth_set_eapTimeout(eap_ctx, TRUE);
		transition(current_session);
		return;
	}
#endif
	// Retransmit the last RADIUS message sent.
	struct wpabuf *buf = radius_msg_get_buf(eap_ctx->last_send_radius);
	int s = eap_ctx->rad_ctx->radius->auth_sock;
	send(s, wpabuf_head(buf), wpabuf_len(buf), 0);

	// Add a new alarm of AAA retransmission.
	add_alarma(current_session->list_of_alarms, current_session, RETR_AAA_TIME, RETR_AAA);	
	return;
}
