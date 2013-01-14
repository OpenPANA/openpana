/**
 * @file mainserver.h
 * @brief  PAA's headers.
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

#ifndef MAINSERVER_H
#define MAINSERVER_H

#include "include.h"

#include "./libeapstack/eap_auth_interface.h"
#include "state_machines/session.h"

/** Maximum length of an udp packet.*/
#define MAX_DATA_LEN 4098
/** Time waited before retransmiting AAA request. */
#define RETR_AAA_TIME 1
/** Maximum number of retransmissions to an AAA server. */
#define MAX_RETR_AAA 3
/** Time to wake up the alarm manager (in miliseconds).*/
#define TIME_WAKE_UP 1000000

/** Task's callback.*/
typedef void* (*task_function)(void* data);

/** List of PANA contexts.*/
struct pana_ctx_list {
	/**PANA context value.*/
    pana_ctx * pana_session;
    /**Pointer to the next PANA context of the list.*/
    struct pana_ctx_list * next;
};

/** List of tasks.*/
struct task_list {
	/** Function to be used with the task.*/
    task_function use_function;
    /** Data of the task.*/
    void* data;
    /** Id session of the task.*/
    //int id_session;
    /**Pointer to the next task of the list.*/
    struct task_list * next;
};


/**Struct of process_receive_eap_ll_msg function's parameter.*/
struct pana_func_parameter {
	/** PaC destination address IPv4. */
    struct sockaddr_in* eap_ll_dst_addr;
    /** PaC destination address IPv4. */
    struct sockaddr_in6* eap_ll_dst_addr6;
    /** PANA message to be sent to PaC.*/
    pana * pana_msg;
    /** Socket's number used for sending the message. */
    int sock;
    /** Alarm's id in case of it has occurred.*/
    int id_alarm;
};

/**Struct of process_retr function's parameter.*/
struct retr_func_parameter {
	/** Identifier of the alarm activated.*/
	int id;
	/** PANA session associated with the alarm. */
	pana_ctx * session;
};

/**Struct of process_receive_radius_msg function's parameter*/
struct radius_func_parameter {
	/** RADIUS message received */
    struct radius_msg * msg;
};

/**
 * A procedure to add a PANA session in the
 * PANA sessions' list managed by the PAA.
 * 
 * @param *session PANA session to add in the list.
 */ 
void add_session(pana_ctx * session);
/**
 * A procedure to add a task in the tasks' list
 * managed by the PAA.
 *
 * @param funcion Callback to function to be executed
 * by some worker thread.
 * @param *arg Arguments of the function pointed by the
 * callback.
 */
void add_task(task_function funcion, void* arg);
/**
 * A procedure to check if exists a new EAP event
 * available. In that case, a PANA state machine's transition
 * is made.
 *
 * @param *pana_session PANA session used in the transition.
 */ 
void check_eap_status(pana_ctx *pana_session);

/**
 * A procedure to get a PANA session from the PANA sessions' list
 * managed by the PAA.
 *
 * @param id Identifier of the PANA session searched.
 *
 * @return A pointer to the PANA session with the identifier searched.
 */ 
pana_ctx* get_session(uint32_t id);
/**
 * A procedure to get a task from the PANA tasks' list managed by
 * the PAA
 *
 * @return A pointer to the a new task available.
 */ 
struct task_list* get_task();
/**
 * A procedure to do the Alarm Manager function in the
 * multithreading framework. Basically, this function consists
 * in looking for the new alarms activated and add new tasks with
 * the information about these new alarms.
 */ 
void* handle_alarm_management();
/**
 * A procedure to do the Alarm Manager function in the
 * multithreading framework. Basically, this function consists in
 * listening to the RADIUS and PANA sockets. When a new message is
 * received, a new task is added with the corresponding information.
 */ 
void* handle_network_management();
/**
 * A procedure to do the Worker function in the
 * multithreading framework. Basically, this function consists in
 * looking for a new task and executing the callback associated to
 * it.
 *
 * @param *data Number for indentifying the worker.
 */ 
void* handle_worker(void* data);
 
/** PAA's main program.*/
int main(int argc, char* argv[]);
/** Procedure that prints the list of alarms for debugging.*/
void print_list_alarms();
/** Procedure that prints the list of sessions for debugging.*/
void print_list_sessions();
/**
 * A procedure to delete a PANA session with the identifier given.
 *
 * @param id Identifier of the PANA session to be deleted.
 */
void remove_session(uint32_t id);
/**
 * A procedure to retransmit an AAA message to AAA server.
 *
 * @param *current_session Pointer to PANA session associated
 * with the retransmission.
 */ 
void retransmitAAA (pana_ctx* current_session);
/** Procedure in charge of handle exit signals sended to the program.
 * @param sig Signal to be handled. */
void signal_handler(int sig);

// Functions used as task
/**
 * A procedure to process a PANA message received
 *
 * @param *arg Arguments necessary to execute the callback
 */ 
void* process_receive_eap_ll_msg(void * arg);
/**
 * A procedure to process a RADIUS message received
 *
 * @param *arg Arguments necessary to execute the callback
 */ 
void* process_receive_radius_msg(void* arg);
/**
 * A procedure to process a retransmission needed.
 *
 * @param *arg Arguments necessary to execute the callback
 */ 
void* process_retr(void *arg);
#endif
