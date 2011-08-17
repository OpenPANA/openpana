/**
 * @file loadconfig.h
 * @brief  Headers of functions wich performs the parser xml file for
 * the PaC and PAA.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 06/07/10.
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


#ifndef LOADCONFIG_H
#define LOADCONFIG_H

#include "include.h"
#include "state_machines/session.h"

/** A procedure to load client's configurable variables.
 *
 * @return 0 if the execution is correct.*/
int load_config_client();
/** A procedure to load server's configurable variables.
 *
 * @return 0 if the execution is correct.*/
int load_config_server();

#endif
