/*
 *  mainservidor.c
 *
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

#include <stdio.h>
#include <stdlib.h> //Function exit
#include <unistd.h> //Function sleep
#include <pthread.h>     /* pthread functions and data structures     */
#include <semaphore.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <config.h>

#include "state_machines/statemachine.h"
#include "state_machines/paamachine.h"
#include "panamessages.h"
#include "state_machines/paamachine.h"
#include "panautils.h"
#include "mainservidor.h"
#include "lalarm.h"
#include "prf_plus.h"

#define RADIUS_PORT 8000


//Global variables
static int fin = FALSE;
char * global_key_id;//Key id is generated from source port and ip of the client

struct pana_ctx_list* list_pana_sessions = NULL; // head of linked list of pana sessions
struct pana_ctx_list* last_pana_sessions = NULL; // pointer to last pana session

struct task_list* list_tasks = NULL; // head of linked list of tasks
struct task_list* last_task = NULL; // pointer to last task

struct lalarm* list_alarms = NULL; // alarms' list

pthread_mutex_t list_sessions_mutex;
pthread_mutex_t list_tasks_mutex;
pthread_mutex_t alarm_list_mutex;
pthread_mutexattr_t request_mutex_attr; //Needed to set attributes to pthread_mutex_t

/* global condition variable for our program. assignment initializes it. */
sem_t got_task; //Semaphore used to wait for new tasks by workers

void signal_handler(int sig) {
    printf("\nStopping server, signal: %d\n", sig);
    fin = 1;
}

void * process_receive_eap_ll_msg(void *arg) {
    struct pana_func_parameter * pana_params = (struct pana_func_parameter*) arg;
    // Current pana session.
    pana_ctx * pana_session;
    pana * msg = pana_params->pana_msg;

    if (ntohs(msg->msg_type) == PCI_MSG) {//If a PCI message is received

		// A session is created to make a transition but it's not saved. It tries to avoid
		// attacks from clients (PCI flood).
        pana_session = malloc(sizeof (pana_ctx));
        if(pana_session == NULL){
			fprintf(stderr,"ERROR: Out of memory.\n");
			exit(1);
		}
        initSession(pana_session); 
		
        //Update variables depends on server
        short port = ntohs(pana_params->eap_ll_dst_addr->sin_port);
        char * ip = inet_ntoa(pana_params->eap_ll_dst_addr->sin_addr);
        pana_session->session_id = generateSessionId(ip, port);
        pana_session->socket = pana_params->sock;
        pana_session->eap_ll_dst_addr = *(pana_params->eap_ll_dst_addr);
		pana_session->server_ctx.global_key_id = global_key_id;
        
        pana_session->list_of_alarms = &(list_alarms);

        //FIXME: Debería comprobarse que pasa cuando un cliente "muere" y ese mismo vuelve a lanzar un PCI
        //Ataque por PCIs falsos para borrar sesiones? reautenticación?
        //Delete the previous session if it exists in the session list and the alarm list
        get_alarm_session(&list_alarms, pana_session->session_id, PCI_ALARM);
        remove_session(pana_session->session_id);
        
        //Add the provisional session in the alarm list
        add_alarma(&(list_alarms), pana_session, TIME_PCI, PCI_ALARM);
        

    }
    else if ((ntohs(msg->msg_type) == PAN_MSG) && // If it is the first answer message
            ((ntohs(msg->flags) & S_FLAG) == S_FLAG)) {// it is created a new session for the new client
       
        //Generate the session id asociated to client's port and ip
        short port = ntohs(pana_params->eap_ll_dst_addr->sin_port);
        char * ip = inet_ntoa(pana_params->eap_ll_dst_addr->sin_addr);
        int session_id = generateSessionId(ip, port); 
#ifdef DEBUG
        fprintf(stderr, "DEBUG: Session-Id added to the list is: %d\n", session_id);
#endif
        
        pana_session = get_alarm_session(&(list_alarms), session_id, PCI_ALARM);
        
        if (pana_session == NULL) {
            fprintf(stderr, "PANA: There isn't a PCI session corresponding with this answer\n");
            return NULL;
        }
     
        pana_session->list_of_alarms = &(list_alarms);
        
        add_session(pana_session);
    } 
    
    else { //If the messsage is another one
        int id = ntohl(msg->session_id); 
#ifdef DEBUG
        fprintf(stderr, "DEBUG: It's gonna search id: %d\n", id);
#endif
        //Check if the session is in the alarm list
        pana_session = get_alarm_session(&(list_alarms), id, PCI_ALARM);
        if (pana_session == NULL) { //If pana_session isn't in the alarm list, it must will be in the session list
            pana_session = get_sesssion(id);
        }
        if (pana_session == NULL) { //If the session doesn't exist
            fprintf(stderr, "PANA: CRITICAL ERROR, tried to send a message from an unauthenticated client.\n");
            return 0;
        }

    }
    
	pthread_mutex_lock(&(pana_session->mutex));
    //Use the correct session
    updateSession((char *)msg, pana_session);
    transition(pana_session);
    check_eap_status(pana_session);
    
    if (pana_session->CURRENT_STATE == CLOSED) {
        remove_alarm(&list_alarms, pana_session->session_id); //Remove the alarms
        remove_session(pana_session->session_id); //Remove the session
        pthread_mutex_unlock(&(pana_session->mutex));
        return 0;
    }
#ifdef DEBUG
    fprintf(stderr, "DEBUG: PANA message treatment finished.\n");
#endif
	pthread_mutex_unlock(&(pana_session->mutex));
    return 0;
}



void* process_receive_radius_msg(void* arg) {
    struct radius_func_parameter radius_params = *((struct radius_func_parameter*) arg);

    int radius_type = RADIUS_AUTH;
    //Get the function's parameters
    struct radius_msg *radmsg = radius_params.radius_msg;
    
    struct radius_client_data *radius_data = get_rad_client_ctx();
    struct radius_hdr *hdr = radius_msg_get_hdr(radmsg);
	struct eap_auth_ctx *eap_ctx = search_eap_ctx_rad_client(hdr->identifier);
                  
    pana_ctx * ll_session = (pana_ctx*) (eap_ctx->eap_ll_ctx);
    pthread_mutex_lock(&(ll_session->mutex));
    
    //Delete the alarm associated to this message
	get_alarm_session(ll_session->list_of_alarms, ll_session->session_id, RETR_AAA);

    if (eap_ctx != NULL) {
		
        radius_client_receive(radmsg, radius_data, &radius_type);
        if ((eap_auth_get_eapReq(eap_ctx) == TRUE)
                || (eap_auth_get_eapSuccess(eap_ctx) == TRUE)) {
		//A transition with PANA ctx is made
#ifdef DEBUG
            fprintf(stderr,"DEBUG: There's an eap request in RADIUS\n");
            fprintf(stderr, "DEBUG: Trying to make a transition with the message from RADIUS\n");
#endif
            transition((pana_ctx *) eap_ctx->eap_ll_ctx);
            pthread_mutex_unlock(&(ll_session->mutex));
            return NULL;
        }
    }
    pthread_mutex_unlock(&(ll_session->mutex));
    return NULL;
}

void add_task(func funcion, void * arg/*, int session_id*/) {
    int rc; /* return code of pthreads functions.  */
    
    struct task_list * new_element; // A new element in the list

    /* create structure with new element */
    new_element = malloc(sizeof (struct task_list));
    if (!new_element) { /* malloc failed?? */
        fprintf(stderr, "add_request: out of memory\n");
        exit(1);
    }
    
    new_element->use_function = funcion;
    new_element->data = arg;
    new_element->next = NULL;

    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(&list_tasks_mutex);

    /* add new session to the end of the list, updating list */
    /* pointers as required */
    if (list_tasks == NULL) { /* special case - list is empty */
        list_tasks = new_element;
        last_task = new_element;
    } else {
        last_task->next = new_element;
        last_task = new_element;
    }


#ifdef DEBUG
    fprintf(stderr,"DEBUG: add_task: added task \n");
#endif /* DEBUG */

    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_tasks_mutex);

    /* signal the condition variable - there's a new task to handle */
    rc = sem_post(&got_task);
}



void add_session(pana_ctx * session) {
    int rc; /* return code of pthreads functions.  */

    struct pana_ctx_list * new_element;

    /* create structure with new request */
    new_element = malloc(sizeof (struct pana_ctx_list));
    if (!new_element) { /* malloc failed?? */
        fprintf(stderr, "add_session: out of memory\n");
        exit(1);
    }
    new_element->pana_session = session;
    new_element->next = NULL;

    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(&list_sessions_mutex);

    /* add new session to the end of the list, updating list */
    /* pointers as required */
    if (list_pana_sessions == NULL) { /* special case - list is empty */
        list_pana_sessions = new_element;
        last_pana_sessions = new_element;
    } 
    else {
        last_pana_sessions->next = new_element;
        last_pana_sessions = new_element;
    }

#ifdef DEBUG
    fprintf(stderr,"DEBUG: add_session: added session \n");
#endif /* DEBUG */

    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_sessions_mutex);

}

pana_ctx* get_sesssion(int id) {
    int rc; /* return code of pthreads functions.  */

    struct pana_ctx_list* session = NULL;

#ifdef DEBUG
    fprintf(stderr, "DEBUG: Trying to get session of id: %d\n", id);
#endif
    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(&list_sessions_mutex);

    if (list_pana_sessions != NULL) {
        session = list_pana_sessions;
        while (session != NULL) {
#ifdef DEBUG
            fprintf(stderr, "DEBUG: Checking id: %d\n", session->pana_session->session_id);
#endif
            if (session->pana_session->session_id == id) break;
            session = session->next;
        }
    }
    
    
    /* unlock mutex */
    rc = pthread_mutex_unlock(&list_sessions_mutex);

    /* return the session to the caller. */
    if (session == NULL) {
#ifdef DEBUG
        fprintf(stderr, "DEBUG: Session not found, id: %d\n", id);
#endif
        return NULL;
    }
    return session->pana_session;
}



void remove_session(int id) {
    int rc;
    
    struct pana_ctx_list* session = NULL;
    struct pana_ctx_list* anterior = NULL;
    
#ifdef DEBUG
    fprintf(stderr, "DEBUG: Trying to delete session with id: %d\n", id);
#endif
    // lock the mutex, to assure exclusive access to the list 
    rc = pthread_mutex_lock(&list_sessions_mutex);

    if (list_pana_sessions != NULL) {
        session = list_pana_sessions;
        //If the session is the first
        if (session->pana_session->session_id == id) {
#ifdef DEBUG
    fprintf(stderr, "DEBUG: Found and deleted session with id: %d\n", id);
#endif
            list_pana_sessions = list_pana_sessions->next;
            session->next=NULL;
            //free(session); //fixme: Cuidado al poner este free. Hay que verlo con el de remove_alarm (lalarm.c)
            rc = pthread_mutex_unlock(&list_sessions_mutex);
            return;
        }
        session = list_pana_sessions->next;
        anterior = list_pana_sessions;
        while (session != NULL) {
            if (session->pana_session->session_id == id) {
                anterior->next = anterior->next->next;
                session->next = NULL;
                //free(session); //fixme: Cuidado al poner este free. Hay que verlo con el de remove_alarm (lalarm.c)
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
    
#ifdef DEBUG
    fprintf(stderr, "DEBUG: Trying to get a task.\n");
#endif
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
#ifdef DEBUG
        fprintf(stderr, "DEBUG: Task not found. \n");
#endif
        return NULL;
    }

    return task;
}

void* handle_worker(void* data) {
    int thread_id = *((int*) data); /* thread identifying number           */
    
#ifdef DEBUG
    fprintf(stderr, "DEBUG: thread '%d' as worker manager\n", thread_id);
#endif

    int rc; /* return code of pthreads functions.  */
    struct task_list* a_task = NULL; /* pointer to a task.               */
    //pthread_mutex_t * mutex;
#ifdef DEBUG
    fprintf(stderr, "DEBUG: Starting thread '%d'\n", thread_id);
#endif

    /* lock the mutex, to access the requests list exclusively. */
    sem_wait(&got_task);

#ifdef DEBUG
    fprintf(stderr, "DEBUG: thread '%d' after pthread_mutex_lock\n", thread_id);
#endif

    /* do forever.... */
    while (!fin) {
#ifdef DEBUG
        fprintf(stderr, "DEBUG: thread '%d' tries to get a task.\n", thread_id);
#endif

        if (list_tasks != NULL) { /* a request is pending */
            a_task = get_task();
        }

        if (a_task) {
/*#ifdef DEBUG
            fprintf(stderr, "DEBUG: Running task. Id session: %d\n", a_task->id_session);
#endif*/
            a_task->use_function(a_task->data);
/*#ifdef DEBUG
            fprintf(stderr, "DEBUG: Ended task. Id session: %d\n", a_task->id_session);
#endif*/
			//FIXME: PEDRO: Habría que liberar esta memoria. El problema está en que
			//cuando la session llega al estado CLOSED, se libera su memoria, y al 
			//intentar liberar la memoria de la tarea, intenta liberar la memoria 
			//de esa session y explota.
			//free(a_task); // Free task's memory
            //Unlock the mutex of this session
            //pthread_mutex_unlock(mutex);
        }
#ifdef DEBUG
        fprintf(stderr, "DEBUG: thread '%d' before pthread_cond_wait\n", thread_id);
#endif
        rc = sem_wait(&got_task);
        /* and after we return from pthread_cond_wait, the mutex  */
        /* is locked again, so we don't need to lock it ourselves */
#ifdef DEBUG
        fprintf(stderr, "DEBUG: thread '%d' after pthread_cond_wait\n", thread_id);
#endif
    }

}

void* handle_network_management() {
    
    //To handle exit signals
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    
    int radius_sock=0; //Init it to a non-valid value
    int eap_ll_sock=0;
    struct sockaddr_in sa;
    fd_set mreadset; /*master read set*/

    rad_client_init();

    eap_ll_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int b = 1;
    // SO_REUSEADDR option is used in case of an unexpected exit, the
    // client will be able to reuse the socket
    if (setsockopt(eap_ll_sock, SOL_SOCKET, SO_REUSEADDR, &b, 4)) {
        perror("setsockopt");
        return 0;
    }
    
    memset((char *) & sa, 0, sizeof (sa));
    sa.sin_family = AF_INET;
    /*FIXME: Para habilitar los inicios de sesión por parte del servidor
     * habría que escuchar en el puerto del servidor (ahora mismo PANAPORT)
     * y aparte en el PANAPORT, de ésta forma el servidor siempre estará
     * pendiente de posibles PCIs (panaport) y podrá iniciar sesiones
     * en su puerto sin que éste tenga que ser el puerto PANA */
    sa.sin_port = htons(SRCPORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

	//Avoid's a warning, bind expects the "const ptr" type
    const struct sockaddr * sockaddr = (struct sockaddr *) & sa;
    if (bind(eap_ll_sock, sockaddr, sizeof (sa)) == -1) {
        perror("Binding socket error:\n");
        return NULL;
    }


    struct radius_client_data *radius_data = get_rad_client_ctx();

    if (radius_data != NULL) {
        radius_sock = radius_data->auth_serv_sock;
    }

    u8 udp_packet[MAX_DATA_LEN];
    struct sockaddr_in eap_ll_dst_addr, radius_dst_addr;
    int addr_size;
    //fixme debería hacerse lo mismo para radius que para pana?
    struct pana_func_parameter *pana_params;
    struct radius_func_parameter radius_params;
    pana *msg;

    while (!fin) {
        FD_ZERO(&mreadset);
        FD_SET(radius_sock, &mreadset);
        FD_SET(eap_ll_sock, &mreadset);
        int ret = select(eap_ll_sock + 1, &mreadset, NULL, NULL, NULL);

        if (ret > 0) {
            //Check pana messages
            if (FD_ISSET(eap_ll_sock, &mreadset)) {
                addr_size = sizeof (eap_ll_dst_addr);
                int length = recvfrom(eap_ll_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(eap_ll_dst_addr), (socklen_t *)&(addr_size));
                if (length > 0) {
                    //FIXME: Cuándo se libera esto
                    msg = calloc(length,1);
                    memcpy(msg,udp_packet,length);
                    //The message will be checked later when the session
                    //is updated
                    //Init the pana function parameters
                    //FIXME: Cuándo se libera esto
                    pana_params = calloc(sizeof(struct pana_func_parameter),1);
                    pana_params->pana_msg = msg;
                    pana_params->eap_ll_dst_addr = &(eap_ll_dst_addr);
                    pana_params->sock = eap_ll_sock;
					pana_params->id_alarm = -1;
                    add_task(process_receive_eap_ll_msg, pana_params/*, ntohl(msg->session_id)*/);
                    
                } else fprintf(stderr,"recvfrom returned ret=%d, errno=%d\n", length, errno);
            }
            //Check radius messages
            if (FD_ISSET(radius_sock, &mreadset)) {
                addr_size = sizeof (radius_dst_addr);
                int length = recvfrom(radius_sock, udp_packet, sizeof (udp_packet), 0, (struct sockaddr *) &(radius_dst_addr), (socklen_t *)&(addr_size));

                if (length > 0) {

                    struct radius_msg *radmsg = radius_msg_parse(udp_packet, length);
                    radius_params.radius_msg = radmsg;
                    
                    add_task(process_receive_radius_msg, &radius_params);
                    
                } else fprintf(stderr,"recvfrom returned ret=%d, errno=%d\n", length, errno);
            }
        }
    }

}

void* handle_alarm_management(void* none) {

    while (!fin){
		struct retr_func_parameter retrans_params;
		struct timeval tv;
		gettimeofday(&tv,NULL);
		struct lalarm* alarm = NULL;
		while ((alarm=get_next_alarm(&list_alarms, tv.tv_sec)) != NULL){
			 retrans_params.session = (pana_ctx *)alarm->pana_session;
			 retrans_params.id = 0;
			 if (alarm->id == PCI_ALARM) {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: A PCI alarm ocurred\n");
	#endif
			} else if (alarm->id == RETR_ALARM) {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: A PANA_RETRANSMISSION alarm ocurred\n");
	#endif
				
				retrans_params.id = RETR_ALARM;
				
				add_task(process_retr, &retrans_params);
			} else if (alarm->id == SESS_ALARM) {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: A SESSION alarm ocurred\n");
	#endif
				
				retrans_params.id = SESS_ALARM;
				add_task(process_retr, &retrans_params);
			} else if (alarm->id == RETR_AAA) {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: An AAA_RETRANSMISSION alarm ocurred\n");
	#endif
				retrans_params.id = RETR_AAA;
				add_task(process_retr, &retrans_params);
				
			} 
			else {
	#ifdef DEBUG
				fprintf(stderr, "DEBUG: An UNKNOWN alarm ocurred\n");
	#endif
			}
		}
		usleep(TIME_WAKE_UP);
	}
}


void* process_retr(void *arg){
	struct retr_func_parameter* retr_params;
	
	retr_params = (struct retr_func_parameter*) arg;
	int alarm_id = retr_params->id;
	pana_ctx * pana_session = retr_params->session;
	
	if (alarm_id == PCI_ALARM) {
#ifdef DEBUG
		fprintf(stderr, "DEBUG: A PCI alarm ocurred\n");
#endif
	} else if (alarm_id == RETR_ALARM) {
#ifdef DEBUG
		fprintf(stderr, "DEBUG: A PANA_RETRANSMISSION alarm ocurred\n");
#endif
		pthread_mutex_lock(&(pana_session->mutex));
		pana_session->RTX_TIMEOUT = 1; 
		transition(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
		
	} else if (alarm_id == SESS_ALARM) {
#ifdef DEBUG
		fprintf(stderr, "DEBUG: A SESSION alarm ocurred\n");
#endif
		
		pthread_mutex_lock(&(pana_session->mutex));
		pana_session->SESS_TIMEOUT = 1; 
		transition(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
		
	} else if (alarm_id == RETR_AAA) {
#ifdef DEBUG
		fprintf(stderr, "DEBUG: An AAA_RETRANSMISSION alarm ocurred\n");
#endif

		pthread_mutex_lock(&(pana_session->mutex));
		retransmitAAA(pana_session);
		pthread_mutex_unlock(&(pana_session->mutex));
		
	} 
	else {
#ifdef DEBUG
		fprintf(stderr, "DEBUG: An UNKNOWN alarm ocurred\n");
#endif
	}
	
}

int main(int argc, char* argv[]) {

    // Variables needed to use threads
    int num_threads = NUM_WORKERS +1; // Workers & network manager
    int i; //loop counter
    int thr_id[num_threads]; // thread IDs
    pthread_t p_threads[num_threads]; // thread's structures

	printf("\n");
	printf(PACKAGE_NAME);
	printf(" Server - ");
	printf(PACKAGE_VERSION);
	printf("\nhttp://openpana.sf.net \n\n\n");
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
    pthread_mutex_init(&alarm_list_mutex, NULL);


    //Init global variables
    list_alarms = crear_alarma(&alarm_list_mutex);

    /* create the request-handling threads */
    for (i = 0; i < NUM_WORKERS; i++) {
        thr_id[i] = i;
        pthread_create(&p_threads[i], NULL, handle_worker, (void*) &thr_id[i]);
        pthread_detach(p_threads[i]);
    }
    
    //Create alarm manager thread
    i+=1;
    thr_id[i] = i;
    pthread_create(&p_threads[i], NULL, handle_alarm_management, (void*) &thr_id[i]);
	
	//Once the workers are executed, the network manager function starts
	handle_network_management();
    printf("PANA: The server has stopped.\n");

// TODO : Before ending:
// - Send PTR to all clients if needed
// - Free al memory allocated
	free(global_key_id);
	
	//Free possible remaining alarms
	#ifdef DEBUG
	fprintf(stderr,"DEBUG: Going to free alarms.\n");
	#endif
	/*pthread_mutex_lock(&alarm_list_mutex);
	struct lalarm * alarm_actual = list_alarms;
	while(alarm_actual != NULL){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Freeing alarm: %d.\n",alarm_actual->id);
		#endif
		struct lalarm * last = alarm_actual;
		alarm_actual = last->sig;
		free(last);
	}
	pthread_mutex_unlock(&alarm_list_mutex);*/
	
	//Free remaining tasks
	#ifdef DEBUG
	fprintf(stderr,"DEBUG: Going to free tasks.\n");
	#endif
	/*list_tasks_mutex;
	pthread_mutex_lock(&list_tasks_mutex);
	struct task_list * actual = list_alarms;
	while(actual != NULL){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Freeing task of session: %d.\n",actual->id_session);
		#endif
		struct task_list * last = actual;
		actual = last->next;
		//free(last);
	}
	pthread_mutex_unlock(&list_tasks_mutex);*/
	
	//Free PANA sessions
	#ifdef DEBUG
	fprintf(stderr,"DEBUG: Going to free sessions.\n");
	#endif
	pthread_mutex_lock(&list_sessions_mutex);
	struct pana_ctx_list * ses_actual = list_pana_sessions;
	while ( ses_actual != NULL ){
		#ifdef DEBUG
		fprintf(stderr,"DEBUG: Freeing session: %d.\n",ses_actual->pana_session->session_id);
		#endif
		if(ses_actual->pana_session->key_id!=NULL){
			free(ses_actual->pana_session->key_id);
		}
		if(ses_actual->pana_session->key_id!=NULL){
			free(ses_actual->pana_session->retr_msg);
		}
		if(ses_actual->pana_session->I_PAR!=NULL){
			free(ses_actual->pana_session->I_PAR);
		}
		if(ses_actual->pana_session->I_PAN!=NULL){
			free(ses_actual->pana_session->I_PAN);
		}
		if(ses_actual->pana_session->PaC_nonce!=NULL){
			free(ses_actual->pana_session->PaC_nonce);
		}
		if(ses_actual->pana_session->PAA_nonce!=NULL){
			free(ses_actual->pana_session->PAA_nonce);
		}
		if(ses_actual->pana_session->msk_key!=NULL){
			free(ses_actual->pana_session->msk_key);
		}
		/* char *LAST_MESSAGE;*/
		
		eap_auth_deinit(&(ses_actual->pana_session->eap_ctx));
		struct pana_ctx_list * last = ses_actual;
		ses_actual = last->next;
		free(last);
	}
	pthread_mutex_unlock(&list_sessions_mutex);
	
    return 0;
}

void check_eap_status(pana_ctx *pana_session) {
    //Check eap status
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Starting to check EAP status (check_eap_status)\n");
#endif
    if (eap_auth_get_eapReq(&(pana_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
        fprintf(stderr,"DEBUG: There's an EAPRequest\n");
#endif
        transition(pana_session);
    }

    if (eap_auth_get_eapSuccess(&(pana_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
        fprintf(stderr,"DEBUG: There's an EAPSUCESS\n");
#endif
        transition(pana_session);
    }
    if (eap_auth_get_eapNoReq(&(pana_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
        fprintf(stderr,"DEBUG: There's an EAP NO REQUEST\n");
#endif
        transition(pana_session);
    }
    if (eap_auth_get_eapTimeout(&(pana_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
        fprintf(stderr,"DEBUG: There's an EAP TIMEOUT\n");
#endif
        transition(pana_session);
    }
    if (eap_auth_get_eapKeyAvailable(&(pana_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
        fprintf(stderr,"DEBUG: There's an EAP KEY AVAILABLE\n");
#endif
        transition(pana_session);
    }
    if (eap_auth_get_eapFail(&(pana_session->eap_ctx)) == TRUE) {
#ifdef DEBUG
        fprintf(stderr,"DEBUG: There's an EAP FAIL\n");
#endif
        transition(pana_session);
    }
#ifdef DEBUG
    fprintf(stderr,"DEBUG: Finished EAP check\n");
#endif
}


int retransmitAAA (pana_ctx* current_session){
	struct eap_auth_ctx * eap_ctx = (struct eap_auth_ctx*) &(current_session->eap_ctx);
#ifdef ISSERVER
	current_session->RTX_COUNTER_AAA +=1;
	if (current_session->RTX_COUNTER_AAA == MAX_RETR_AAA){
		eap_auth_set_eapTimeout(eap_ctx, TRUE);
		transition(current_session);
		return 1;
	}
#endif
	struct wpabuf *buf = radius_msg_get_buf(eap_ctx->last_send_radius);
	int s = eap_ctx->rad_ctx->radius->auth_sock;
	send(s, wpabuf_head(buf), wpabuf_len(buf), 0);
	
	add_alarma(current_session->list_of_alarms, current_session, RETR_AAA_TIME, RETR_AAA);	
	return 0;
}
