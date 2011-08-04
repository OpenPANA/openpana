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

/** Alarm types identifiers*/
#define PCI_ALARM  1
#define RETR_ALARM 2
#define SESS_ALARM 3
#define RETR_AAA   4

/** Struct that represents an alarms' list*/
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
/** Creates a new alarm list.
 *
 * @return A pointer to the alarms' list initialized.*/
struct lalarm* init_alarms();
/** Adds a new alarm to a list.
 * @param **l Alarms' list where the new alarm must be added.
 * @param *session PANA session associated to the alarm to add.
 * @param tiempo Expiration time of the alarm added.
 * @param iden Type identifier of the alarm added.
 *
 * @return A pointer to the alarms' list with the new alarm added.*/
struct lalarm* add_alarma(struct lalarm ** l, pana_ctx* session, time_t tiempo, int iden);

/** Returns the alarm requested and removes it from the list.
 * @param **list Alarms' list where the alarm must be obtained.
 * @param id_session PANA session identifier which must be obtained.
 * @param id_alarm Alarm type identifier which must be obtained.
 *
 * @return A pointer to the PANA session corresponding with the alarm searched.*/
pana_ctx * get_alarm_session(struct lalarm** list, int id_session, int id_alarm);

/** Return the first alarm in the alarms' list if it is activated. However, either if the alarms' list is empty
 * or the first alarm is not activated, the function returns a NULL pointer.
 * @param **list Alarms' list from where the alarm must be obtained.
 * @param time Timestamp used for calculating if the first alarm is activated.
 *
 * @return The first alarm in the list if it is activated. A NULL pointer if the alarms' list is empty or the
 * first is not activated.*/
struct lalarm * get_next_alarm(struct lalarm** list, time_t time);
/**
 * A procedure to remove the alarms associated to a PANA session.
 *
 * @param **list Alarms' list where the alarms must be removed.
 * @param id_session PANA session identifier whose alarms associated must be removed from the list.
 */ 
void remove_alarm(struct lalarm** list, int id_session);
#endif
