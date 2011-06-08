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

#define MAX_DATA_LEN 2048
#define RETR_AAA_TIME 1 //Time waited before retransmiting aaa request
#define MAX_RETR_AAA 3  // Max. number of retransmissiones to aaa's server
#define TIME_WAKE_UP 1000000 //Time to wake up the alarm manager (in miliseconds). 

#include "./libeapstack/eap_auth_interface.h"
#include "state_machines/session.h"

typedef void* (*func)(void* data);

void increase_one(char *value, int length);
void add_session(pana_ctx * session);
void remove_session(int id);
void add_task(func funcion, void* arg, int session_id);
void add_mutex(int id);
pthread_mutex_t* get_mutex(int id);
void check_eap_status(pana_ctx *pana_session);
pana_ctx* get_sesssion(int id);
int generateSessionId(char * ip, short port);
int retransmitAAA (pana_ctx* current_session);

// Callbacks used as tasks


// Format a list of pana contexts

struct pana_ctx_list {
    pana_ctx * pana_session;
    struct pana_ctx_list * next;
};

// Format a list of tasks

struct task_list {
    func use_function;
    void* data;
    int id_session;
    struct task_list * next;
};



//Format a process_receive_eap_ll_msg function's parameter

struct pana_func_paramater {
    struct sockaddr_in* eap_ll_dst_addr;
    panaMessage * pana_msg;
    int sock;
    int id_alarm;
};

//Format a process_retr function's parameter

struct retr_func_parameter {
	int id;
	pana_ctx * session;
};

//Format a process_receive_radius_msg function's parameter

struct radius_func_parameter {
    struct eap_auth_ctx * context_eap;
    struct radius_msg *radius_msg;
    struct radius_client_data *rad_data;
};

struct mutex_list {
    pthread_mutex_t mutex;
    int session_id;
    struct mutex_list* next;
};

// Functions used as task
void* process_receive_eap_ll_msg(void * arg);
void* process_receive_radius_msg(void* arg);
void* process_retr(void *arg);


