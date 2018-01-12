/* decrypts the encrypted name or password stored by M$ SMS in a TCF File
   Copyright (C) 2007 Harry Basalamah

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* version history
   26.01.2007
   initial version
  
   27.01.2007
   cut out a couple of variables and let argv[n] do the job
   makes readability worse, but code smaller
  
   01.01.2018
   code cosmetics */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage();

int main(int argc, char *argv[]) {
 unsigned int count;
 unsigned long convert, action;
 char temp[3] = { 0 };
 unsigned short XORtable[] = {
 0x7F, 0xBA, 0xDC, 0x83,
 0x55, 0x48, 0xF6, 0xD3,
 0xAF, 0x4F, 0x05, 0xD5,
 0x6F, 0x25, 0x81, 0x97,
 0x0D, 0x4F, 0x9C, 0x1C,
 0xF9, 0x28, 0x1F, 0xD1,
 0x6F, 0x23, 0xB7, 0xA7,
 0xF3, 0x88, 0xB4, 0xA1,
 0xA6, 0x26, 0xDD, 0x22,
 0x79, 0x8A, 0x01 }, len, NorPtable[39];

 if (argc != 4)
  usage();

 if (strlen(argv[1]) != 78 || strlen(argv[2]) != 42) /*  a bit of error handling */
  usage();
 action = strtoul(argv[3], NULL, 10);
 if (action < 0 || action > 1)
  usage();

 /* convert name / password from ASCII to HEX, (un)mask and save it */ 
 len = strlen(argv[1]);
 for (count = 0; count < len/2; count++) {
  temp[0] = argv[1][count * 2];
  temp[1] = argv[1][count * 2 + 1];
  convert = strtoul(temp, NULL, 16);
  NorPtable[count] = (short)convert ^ XORtable[count]; 
 }

/* determine decrypted code length */
 len = NorPtable[0] ^ argv[2][0];
 if (action)
  len = len ^ 0xA2;

 if (len > 39) /* we'll abort if len > 39 chars (might happen if user mixes */
  exit(1);     /* up the last parameter) */ 

 printf("\nDecrypted data (length=%d): \"", len);
 for (count = 1; count <= len; count++) {
  temp[0] = NorPtable[count] ^ argv[2][count % 21]; /* WTF? */
  if (action) /* only the first 20 chars of the key are used for decryption */
   temp[0] ^= 0xA2;
  printf("%c", temp[0]);
 }
 printf("\"\nCheers!");
 exit(0);
}

void usage(void) {
 printf("Name/Password decryption for MS SMS TCF files\nCoded by Harry Basalamah 01/2007\n\n");
 printf("Usage: tcfnpdecrypt <encrypted name or password> <key> <0 || 1>\n%");
 printf("Use '0' to indicate you want to decode a name, '1' for password\n");
 exit(1);
}
