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

#include "lalarm.h"
#include <time.h>

/* Proceso que inicializa el listado, lanzado en user_inicializar */
struct lalarm *init_alarms(pthread_mutex_t * mutex_list) {
    mutex = mutex_list;
    return NULL;

}

/* Inserta una alarma*/
struct lalarm * add_alarma(struct lalarm ** l, 
							pana_ctx* session, 
							time_t time, 
							int iden) {

	/*
	pthread_mutex_lock(mutex);
	struct timeval tv;
	gettimeofday(&tv, NULL);
    time_t tiempo = tv.tv_sec;
    tiempo += time;

    if ((*l)==NULL){ //The alarm list is empty

		(*l) = malloc (sizeof(struct lalarm));
		(*l)->pana_session = session;
		(*l)->tmp = tiempo;
		(*l)->id = iden;
		(*l)->sig = NULL;
	}

	else if ((difftime((*l)->tmp, tiempo) == 0) || (difftime((*l)->tmp, tiempo) > 0)) { // If the new alarm must be set the first one
		struct lalarm * point_to_list = (*l);
		(*l) = malloc (sizeof(struct lalarm));
		(*l)->pana_session = session;
		(*l)->tmp = tiempo;
		(*l)->id = iden;
		(*l)->sig = point_to_list;
	}

	else if ((*l)->sig == NULL){ // If only there is an alarm, the new alarm will be the second one.
		(*l)->sig = malloc (sizeof(struct lalarm));
		(*l)->sig->pana_session = session;
		(*l)->sig->tmp = tiempo;
		(*l)->sig->id = iden;
		(*l)->sig->sig = NULL;
	}

	else {
		struct lalarm * prev = (*l);
		struct lalarm * ptr = (*l)->sig;
		//int final = 0;
		while ((difftime(ptr->tmp, tiempo)<0) && (ptr->sig !=NULL)){
				prev = ptr;
				ptr = ptr->sig;
		}

		if ((difftime(ptr->tmp, tiempo)>0) || (difftime(ptr->tmp, tiempo)==0)){ // The new alarm must be set between two alarms
			prev->sig = malloc (sizeof(struct lalarm));
			prev->sig->pana_session = session;
			prev->sig->tmp = tiempo;
			prev->sig->id = iden;
			prev->sig->sig = ptr;
		}

		else { //The new alarm must be set in the last position of alarm's list
			ptr->sig = malloc (sizeof(struct lalarm));
			ptr->sig->pana_session = session;
			ptr->sig->tmp = tiempo;
			ptr->sig->id = iden;
			ptr->sig->sig = NULL;
		}
	}

	pthread_mutex_unlock(mutex);
    return (*l);
	*/





    								
    pthread_mutex_lock(mutex);
    struct timeval tv; 
    gettimeofday(&tv, NULL);
    time_t tiempo = tv.tv_sec;
    tiempo += time;
    struct lalarm *anterior = *l;
    int final = 0; //Booleano para encontrar el sitio de inserción
    if (anterior == NULL) { // Si la lista es vacía
        (*l) = malloc(sizeof (struct lalarm));
        (*l)->pana_session = session;
        (*l)->tmp = tiempo; //Guardo el tiempo de la alarma
        (*l)->id = iden;
        (*l)->sig = NULL;
    } else {
        struct lalarm *aux = (*l);
        while (difftime(aux->tmp, tiempo) < 0 && final == 0) {// Recorremos hasta el sitio de inserción

            if (aux->sig == NULL)//Si llegamos al final
                final = 1;
            else {
                anterior = aux;
                aux = aux->sig;
            }
        }

        if (final == 1) {// Si tiene que insertar al final
            aux->sig = malloc(sizeof (struct lalarm));
            aux->sig->pana_session = session;
            aux->sig->tmp = tiempo; //Guardo el tiempo de la alarma
            aux->sig->id = iden;
            aux->sig->sig = NULL;
        } else if (difftime(aux->tmp, tiempo) > 0) { //Si tiene que insertar en un lugar intermedio hay 2 casos:
            // 		- Si el anterior = l es que hay que insertar en la primera posición
            //		- Sino, hay que insertar en algún lugar intermedio
            if (aux == (*l)) { //Hay que insertar en la primera posición
                (*l) = malloc(sizeof (struct lalarm));
                (*l)->pana_session = session;
                (*l)->tmp = tiempo; //Guardo el tiempo de la alarma
                (*l)->id = iden;
                (*l)->sig = anterior; //El siguiente es el que ya había antes como "primero".
                //Si hay que insertar en la primera posición, hay que quitar la alarma
                //que ya había puesta y poner la nueva primera de la lista
                
            } else { //Inserta en un lugar que es intermedio.
                anterior->sig = malloc(sizeof (struct lalarm));
                anterior->sig->pana_session = session;
                anterior->sig->tmp = tiempo; //Guardo el tiempo de la alarma
                anterior->sig->id = iden;
                anterior->sig->sig = aux;
            }
        } else if (difftime(aux->tmp, tiempo) == 0) { //Si dos alarmas coinciden, se inserta también
            struct lalarm *aux2 = anterior->sig;
            anterior->sig = malloc(sizeof (struct lalarm));
            anterior->sig->pana_session = session;
            anterior->sig->tmp = tiempo; //Guardo el tiempo de la alarma
            anterior->sig->id = iden;
            anterior->sig->sig = aux2;
        }



    }
    pthread_mutex_unlock(mutex);
    return (*l);

}

pana_ctx * get_alarm_session(struct lalarm** list, int id_session, int id_alarm) {
    pthread_mutex_lock(mutex);
    struct lalarm* session = NULL;
    struct lalarm* anterior = NULL;
    if (list == NULL) {
        pthread_mutex_unlock(mutex);
        return NULL;
    }
    if ((*list) != NULL) {
		if ((*list)->pana_session!=NULL){
			if ((*list)->pana_session->session_id == id_session && (*list)->id == id_alarm) { //If the alarm is the first
				session = (*list);
				*list = (*list)->sig;
				session->sig = NULL;
			}
        } else {
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

    /* return the request to the caller. */
    if (session == NULL) {
#ifdef DEBUG
        fprintf(stderr, "DEBUG: Session with id %d not found.\n", id_session);
#endif
        pthread_mutex_unlock(mutex);
        return NULL;
    }
    pthread_mutex_unlock(mutex);
    return session->pana_session;
}

struct lalarm * get_next_alarm(struct lalarm** list, time_t time) {
	pthread_mutex_lock(mutex);
	if ((*list)==NULL){
		pthread_mutex_unlock(mutex);
		return NULL;
	}
	
	if ((*list)->tmp<time){
		struct lalarm* first = (*list);
		(*list) = (*list)->sig;
		first->sig = NULL;
		pthread_mutex_unlock(mutex);
		return first;
	}
	else {
		pthread_mutex_unlock(mutex);
		return NULL;
	}
}

void remove_alarm(struct lalarm** list, int id_session){
	pthread_mutex_lock(mutex);
	
	if(list == NULL || (*list) == NULL){
		pthread_mutex_unlock(mutex);
		return;
	}

	if ((*list)->pana_session == NULL)
		fprintf(stderr, "ERROR: Trying to remove a session in an alarm's list empty\n");
	while((*list)->pana_session->session_id == id_session){
		struct lalarm * tofree = (*list);
		(*list) = (*list)->sig;
		free(tofree);
		//pthread_mutex_unlock(mutex);
		//return;
	}
	
	if (list != NULL && (*list) != NULL){
		
		struct lalarm* current = (*list)->sig;
		struct lalarm* prev = (*list);
		while(current!=NULL){
			#ifdef DEBUG
			if(current->pana_session == NULL){
				fprintf(stderr,"DEBUG: remove_alarm: NULL Session \n");
				exit(1);
			}
			#endif
			if(current->pana_session->session_id == id_session){
					struct lalarm * tofree = current;
					prev->sig = current->sig;
					tofree->sig = NULL;
					free(tofree);
			}
			
			prev = current;
			current = current->sig;		
		}
		
	}

	
	pthread_mutex_unlock(mutex);
	return;
}
