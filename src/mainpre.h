/**
 * @file mainpre.h
 * @brief  PRE's headers.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez on 30/04/12.
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

#ifndef MAINPRE_H
#define MAINPRE_H

#include "include.h"

#define MAX_DATA_LEN 4098

//Variables needed for PRE communications

int IP_VERSION;
char * IP_LISTEN_PAC;
short PORT_LISTEN_PAC;
char * IP_LISTEN_PAA;
short PORT_LISTEN_PAA;
char * IP_PAA;
short PORT_PAA;

#endif
