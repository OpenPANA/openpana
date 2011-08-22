/**
 * @file lalarm.c
 * @brief Implements a linked list to manage alarms.
 */
/*
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

#include "lalarm.h"
#include "panautils.h"

/** Global mutex used for controling the access to the critical lines of code.*/
pthread_mutex_t mutex;


/* A procedure to init the alarms' list. */
struct lalarm *init_alarms() {
    pthread_mutex_init(&mutex, NULL);
    return NULL;

}

/* Add an alarm*/
struct lalarm * add_alarma(struct lalarm ** l, 
							pana_ctx* session, 
							double time, 
							int iden) {
	// Set the mutex for entering in the critical section.
    pthread_mutex_lock(&mutex);

    // Get the actual timestamp

    double tiempo = getTime();
    tiempo += time;
    
    struct lalarm *anterior = *l;
    bool final = 0; //Bool for searching the place of the new alarm in the list.
    if (anterior == NULL) { // If the list is empty
		// Save the alarm's information
        (*l) = XMALLOC(struct lalarm,1);
        (*l)->pana_session = session;
        (*l)->tmp = tiempo; 
        (*l)->id = iden;
        (*l)->sig = NULL;
    } else {
        struct lalarm *aux = (*l);
        while (difftime(aux->tmp, tiempo) < 0 && final == 0) {//Search the place where the new alarm 

            if (aux->sig == NULL)//If we reach the end of the alarm list
                final = TRUE;
            else {
                anterior = aux;
                aux = aux->sig;
            }
        }

        if (final) {// If the new alarm must be inserted in the end of the alarms' list
            aux->sig = XMALLOC(struct lalarm,1);
            aux->sig->pana_session = session;
            aux->sig->tmp = tiempo; 
            aux->sig->id = iden;
            aux->sig->sig = NULL;
        } else if (difftime(aux->tmp, tiempo) > 0) { //If the place of the new alarm is between the start and the end, whe have two options:
            // 		- If anterior == l the new alarm must be inserted in the first position.
            //		- Else, the new alarm must be inserted in an intermediate position.
            if (aux == (*l)) { // We have to insert the new alarm in the first position
                (*l) = XMALLOC(struct lalarm,1);
                (*l)->pana_session = session;
                (*l)->tmp = tiempo; 
                (*l)->id = iden;
                (*l)->sig = anterior; //The next alarm is the old first alarm in the list.
                
            } else { //Insert the new alarm in an intermediate position.
                anterior->sig = XMALLOC(struct lalarm,1);
                anterior->sig->pana_session = session;
                anterior->sig->tmp = tiempo; 
                anterior->sig->id = iden;
                anterior->sig->sig = aux;
            }
        } else if (difftime(aux->tmp, tiempo) == 0) { //If two alarms are at the same time, they are inserted too.
            struct lalarm *aux2 = anterior->sig;
            anterior->sig = XMALLOC(struct lalarm,1);
            anterior->sig->pana_session = session;
            anterior->sig->tmp = tiempo; 
            anterior->sig->id = iden;
            anterior->sig->sig = aux2;
        }

    }
    //Unlock the mutex.
    pthread_mutex_unlock(&mutex);
    return (*l);

}

pana_ctx * get_alarm_session(struct lalarm** list, uint32_t id_session, int id_alarm) {

	//Lock the mutex for entering in the critical section.
    pthread_mutex_lock(&mutex);
    
    struct lalarm* session = NULL;
    struct lalarm* anterior = NULL;
    if (list == NULL) { // If the alarms' list is empty.
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    
    if ((*list) != NULL) {
		if ((*list)->pana_session!=NULL){
			if ((*list)->pana_session->session_id == id_session && (*list)->id == id_alarm) { //If the alarm is the first
				session = (*list);
				*list = (*list)->sig;
				session->sig = NULL;
			}

			else { //If the alarm is in an intermediate position.
				session = (*list)->sig;
				anterior = (*list);
				while (session != NULL) {
					if ((*list)->pana_session!=NULL){
						if (session->pana_session->session_id == id_session && session->id == id_alarm) {
							anterior->sig = anterior->sig->sig;
							session->sig = NULL;
							break;
						}
					}
					anterior = anterior->sig;
					session = session->sig;
				}
			}
        } 
    }

    /* return the request to the caller. */
    if (session == NULL) {
		pana_debug("Session with id %d not found in the alarm list", id_session);
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    pthread_mutex_unlock(&mutex);
    return session->pana_session;
}

// Get the first alarm of the alarms' list if it is activated.
struct lalarm * get_next_alarm(struct lalarm** list, double time) {

	//Lock the mutex for entering in the critical section.
	pthread_mutex_lock(&mutex);
	if ((*list)==NULL){ //If the list is empty.
		pthread_mutex_unlock(&mutex);
		return NULL;
	}
	
	if ((*list)->tmp<time){ //If the first alarm is activated.
		struct lalarm* first = (*list);
		(*list) = (*list)->sig;
		first->sig = NULL;
		pthread_mutex_unlock(&mutex);
		return first;
	}
	else { //If the first alarm is not activated.
		pthread_mutex_unlock(&mutex);
		return NULL;
	}
}

// Remove the alarms associated to a PANA session.
void remove_alarm(struct lalarm** list, uint32_t id_session){

	//Lock the mutex for entering to the critical section.
	pthread_mutex_lock(&mutex);
	
	if(list == NULL || (*list) == NULL){ //If the list is empty.
		pthread_mutex_unlock(&mutex);
		return;
	}

	if ((*list)->pana_session == NULL){
		pana_error("Trying to remove a session in an alarm's list empty");
	}
	while( ((*list) != NULL) && ((*list)->pana_session->session_id == id_session)){ //Removed the firsts alarms associated with the PANA session searched.
		struct lalarm * tofree = (*list);
		(*list) = (*list)->sig;
		XFREE(tofree);
	}
	
	if (list != NULL && (*list) != NULL){ //If we don't reach the end of the list, search more alarms associated with the PANA session searched.
		
		struct lalarm* current = (*list)->sig;
		struct lalarm* prev = (*list);
		while(current!=NULL){
			if(current->pana_session == NULL){
				pana_fatal("remove_alarm used with a NULL Session");
			}
			if(current->pana_session->session_id == id_session){
					struct lalarm * tofree = current;
					prev->sig = current->sig;
					tofree->sig = NULL;
					XFREE(tofree);
			}
			
			prev = current;
			current = current->sig;		
		}
		
	}

	//Unlock the mutex.
	pthread_mutex_unlock(&mutex);
	return;
}
