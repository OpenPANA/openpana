/**
 * @file cmac.h
 * @brief  CMAC function header.
 **/
/* 
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 04/04/12.
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
#ifndef CMAC_H
#define CMAC_H
void AES_CMAC ( unsigned char *key, unsigned char *input, int length,
                  unsigned char *mac );

#endif
