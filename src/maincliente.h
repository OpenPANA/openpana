/* 
 *  maincliente.h
 *	
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 16/11/10.
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

#ifndef MAINCLIENTE_H
#define	MAINCLIENTE_H

/** Time to wake up the alarm manager (in miliseconds).*/
#define TIME_WAKE_UP 1000000
/** Maximum size to use while receiving a packet. */
#define MAX_DATA_LEN 2048

/** Procedure that periodically checks if there's any active alarm and 
 * if needed calls the alarm function.*/
void* handle_alarm_management(void* none);
/** Procedure in charge of handle exit signals sended to the program.
 * @param sig Signal to be handled. */
void signal_handler(int sig);
/** PaC's main program.*/
int main(int argc, char *argv[]);

#endif	/* _MAINCLIENTE_H */
