/*
 *  mainservidor.h
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

#ifndef MAINSERVIDOR_H
#define MAINSERVIDOR_H
#include "./libeapstack/eap_auth_interface.h"
#include "state_machines/session.h"

#define MAX_DATA_LEN 2048
/**Time waited before retransmiting AAA request. */
#define RETR_AAA_TIME 1
/**Max. number of retransmissions to an AAA server. */
#define MAX_RETR_AAA 3
/** Time to wake up the alarm manager (in miliseconds).*/
#define TIME_WAKE_UP 1000000

typedef void* (*func)(void* data);

/** List of PANA contexts.*/
struct pana_ctx_list {
	/**PANA context value.*/
    pana_ctx * pana_session;
    /**Pointer to the next PANA context of the list.*/
    struct pana_ctx_list * next;
};

/** List of tasks*/
struct task_list {
	/** Function to be used with the task.*/
    func use_function;
    /** Data of the task.*/
    void* data;
    /** Id session of the task.*/
    //int id_session;
    /**Pointer to the next task of the list.*/
    struct task_list * next;
};


/**Struct of process_receive_eap_ll_msg function's parameter*/
struct pana_func_parameter {
    struct sockaddr_in* eap_ll_dst_addr;
    pana * pana_msg;
    int sock;
    int id_alarm;
};

/**Struct of process_retr function's parameter*/
struct retr_func_parameter {
	int id;
	pana_ctx * session;
};

/**Struct of process_receive_radius_msg function's parameter*/
struct radius_func_parameter {
    struct radius_msg * msg;
};

void add_session(pana_ctx * session);
void add_task(func funcion, void* arg);
void check_eap_status(pana_ctx *pana_session);
int generateSessionId(char * ip, short port);
pana_ctx* get_session(int id);
struct task_list* get_task();
void* handle_alarm_management(void* none);
void* handle_network_management();
void* handle_worker(void* data);
void remove_session(int id);
int retransmitAAA (pana_ctx* current_session);


// Functions used as task
void* process_receive_eap_ll_msg(void * arg);
void* process_receive_radius_msg(void* arg);
void* process_retr(void *arg);
#endif
