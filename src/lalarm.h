/*
 *	lalarm.c 
 * 
 *  Implements a linked list to manage alarms.
 * 
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 13/04/09.
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

#ifndef _Alarmas_
#define _Alarmas_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h> //Para el tratamiento de las estructuras time_t y los tiempos 
#include <signal.h> //Para el tratamiento y uso de señales entre procesos
#include "state_machines/session.h"

#define PCI_ALARM  1
#define RETR_ALARM 2
#define SESS_ALARM 3
#define RETR_AAA   4


struct lalarm {
	/** PANA session associated to the alarm. */
    pana_ctx* pana_session;
    /** Alarm's start time.*/ 
    time_t tmp;
    /** Next element */
    struct lalarm * sig;
    /** Alarm's id.*/
    int id;
};
/** Creates a new alarm list. */
struct lalarm* init_alarms();
/** Adds a new alarm to a list.*/
struct lalarm* add_alarma(struct lalarm ** l, pana_ctx* session, time_t tiempo, int iden);
/** Returns the alarm requested and removes it from the list.*/
pana_ctx * get_alarm_session(struct lalarm** list, int id_session, int id_alarm);

struct lalarm * get_next_alarm(struct lalarm** list, time_t time);
void remove_alarm(struct lalarm** list, int id_session);
#endif
