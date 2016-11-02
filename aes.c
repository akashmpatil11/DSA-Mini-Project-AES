/*****************************************************************************
 * AES Encryption-Decryption in C
 *
 * Copyright (C) Akash Patil akashmpatil11@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define Nr 10

/*
 * S-box transformation table
 */
uint8_t s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f

/*
 * Inverse S-box transformation table
 */
uint8_t inv_s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};// f

/*
 * Multiplies two 8 bit no.s in GF(2^8)
 * Returns 8 bit no.
 */ 
uint8_t gmul(uint8_t a, uint8_t b) {

	uint8_t prod = 0, i, hbs = 0;
	for(i = 0; i < 8; i++){
		if(b & 1)
			prod = prod ^ a;
		hbs = a & 0x80;
		a = a << 1;
		if(hbs)
			a = a ^ 0x1b;
		b = b >> 1;
	}
	return prod;
}

/*
 *Function to shift 4 bytes of word left  
 */
void ShiftLeft(uint8_t *str, uint8_t base) {
	uint8_t tmp;
	tmp = str[base];
	str[base] = str[base + 1];
	str[base + 1] = str[base + 2];
	str[base + 2] = str[base + 3];
	str[base + 3] = tmp;
}

/*
 *Function to shift 4 bytes of word right
 */
void ShiftRight(uint8_t *str, uint8_t base) {
        uint8_t tmp;
	tmp = str[base + 3];
	str[base + 3] = str[base + 2];
	str[base + 2] = str[base + 1];
	str[base + 1] = str[base];
	str[base] = tmp;
}

/*
 *Each round has its own round key 
 *that is derived from the original 128-bit encryption key
 *This keys are used for both encryption and decryption step
 */

void RoundKey(uint8_t *key, uint8_t *word) {
	uint8_t i, j, t[4], row, column;
	uint8_t RCon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
	for(i = 0; i < 4; i++) {
		word[4 * i + 0] = key[4 * i + 0];
		word[4 * i + 1] = key[4 * i + 1];
		word[4 * i + 2] = key[4 * i + 2];
		word[4 * i + 3] = key[4 * i + 3];
	}
	for(i = 4; i < 44; i++) {
		if(i % 4 != 0) {
			word[4 * i + 0] = word[4 * i + 0 - 4 * 1] ^ word[4 * i + 0 - 4 * 4];
			word[4 * i + 1] = word[4 * i + 1 - 4 * 1] ^ word[4 * i + 1 - 4 * 4];
			word[4 * i + 2] = word[4 * i + 2 - 4 * 1] ^ word[4 * i + 2 - 4 * 4];
			word[4 * i + 3] = word[4 * i + 3 - 4 * 1] ^ word[4 * i + 3 - 4 * 4];
		}
		else {
			t[0] = word[4 * (i-1) + 0];
			t[1] = word[4 * (i-1) + 1];
			t[2] = word[4 * (i-1) + 2];
			t[3] = word[4 * (i-1) + 3];
			
			ShiftLeft(t, 0);
 
			for(j = 0; j < 4 ; j++) {
				column = (t[j] & 0xf0) >> 4;
				row = t[j] & 0x0f;
				if(j == 0)
					t[j] = s_box[16 * column + row] ^ RCon[(i / 4) - 1];
				else
					t[j] = s_box[16 * column + row] ^ (0x00) ;
			}

                        word[4 * i + 0] = t[0] ^ word[4 * i + 0 - 4 * 4];
                        word[4 * i + 1] = t[1] ^ word[4 * i + 1 - 4 * 4];
                        word[4 * i + 2] = t[2] ^ word[4 * i + 2 - 4 * 4];
                        word[4 * i + 3] = t[3] ^ word[4 * i + 3 - 4 * 4];
		}  
	}
}

/*
 *Function to add roundkey for rth round
 */

void AddRoundKey(uint8_t *state, uint8_t *word, uint8_t r) {
	uint8_t i;
	for(i = 0; i < 4; i++) {
		state[4 * i + 0] = state[4 * i + 0] ^ word[16 * r + i + 4 * 0]; 	
		state[4 * i + 1] = state[4 * i + 1] ^ word[16 * r + i + 4 * 1];
		state[4 * i + 2] = state[4 * i + 2] ^ word[16 * r + i + 4 * 2]; 	
		state[4 * i + 3] = state[4 * i + 3] ^ word[16 * r + i + 4 * 3];
	} 
}

/*
 *Byte-by-byte substitution using a rule that stays the
 *same in all encryption rounds.
 *The bytes is substitued according to s-box
 */
void SubByte(uint8_t *state) {
	uint8_t i;
	for(i = 0; i < 16; i++)
		state[i] = s_box[16 * ((state[i] & 0xf0) >> 4) + (state[i] & 0x0f)];
}

/*
 *The ShiftRows transformation consists of 
 *not shifting the first row of the state array at all
 *circularly shifting the second row by one byte to the left
 *circularly shifting the third row by two bytes to the left
 *circularly shifting the last row by three bytes to the left.
 */
void RowShift(uint8_t *state) {
	uint8_t row, i;
	for(row = 1; row < 4; row++){
		for(i = 1; i <= row; i++)
			ShiftLeft(state, 4 * row);
	}
}

/*
 *This step replaces each byte in a column by two times
 *that byte, plus three times the the next byte,
 *plus the byte that comes next, plus the byte that follows.
 */
void MixColumn(uint8_t *state) {
	uint8_t i, j, a[4];
	uint8_t R[4][4] = {0x02, 0x03, 0x01, 0x01,
			   0x01, 0x02, 0x03, 0x01,	
			   0x01, 0x01, 0x02, 0x03,
			   0x03, 0x01, 0x01, 0x02};
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			a[j] = gmul(R[j][0], state[0 + i]) ^ gmul(R[j][1], state[4 + i]) ^ gmul(R[j][2], state[8 + i]) ^ gmul(R[j][3], state[12 + i]);
		}
		for(j = 0; j < 4; j++)
			state[4 * j + i] = a[j];	
	}
}

/*
 *This function encryptes data
 *for first 10 rounds MixColumn is done along with SubBtyes, Rowshift and AddRoundkey
 *but for last round Mixcolumn is not done 
 */
void Cipher(char *orig, char *encry, uint8_t *word) {
	uint8_t state[16], i, j, r;
	/*Copies original data into state(which is used for all round as data to be encrypted)*/
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			state[4 * i + j] = orig[4 * j + i];
	}

	AddRoundKey(state, word, 0);
	for(r = 1; r < Nr; r++) {
		SubByte(state);
		RowShift(state);
		MixColumn(state);
		AddRoundKey(state, word, r);
	}

	SubByte(state);
	RowShift(state);
	AddRoundKey(state, word, Nr);
	/*Save state[16] to encry[]*/	
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			encry[4 * j + i] = state[4 * i + j];
	}
}

/*
 *Byte-by-byte substitution using a rule that stays the
 *same in all encryption rounds.
 *The bytes is substitued according to inv_s_box
 */
void InvSubByte(uint8_t *state) {
	uint8_t i;
	for(i = 0; i < 16; i++)
		state[i] = inv_s_box[16 * ((state[i] & 0xf0) >> 4) + (state[i] & 0x0f)];
}

/*
 *The InvShiftRows transformation consists of 
 *not shifting the first row of the state array at all
 *circularly shifting the second row by one byte to the right
 *circularly shifting the third row by two bytes to the right
 *circularly shifting the last row by three bytes to the right
 */
void InvRowShift(uint8_t *state) {
	uint8_t row, i;
	for(row = 1; row < 4; row++){
		for(i = 1; i <= row; i++)
			ShiftRight(state, 4 * row);
	}
}

/*
 *Same as MixColumn, but multiplying factors are differnt
 */
void InvMixColumn(uint8_t *state) {
	uint8_t i, j, a[4];
	uint8_t R[4][4] = {0x0e, 0x0b, 0x0d, 0x09,
			   0x09, 0x0e, 0x0b, 0x0d,	
			   0x0d, 0x09, 0x0e, 0x0b,
			   0x0b, 0x0d, 0x09, 0x0e};

	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			a[j] = gmul(R[j][0], state[0 + i]) ^ gmul(R[j][1], state[4 + i]) ^ gmul(R[j][2], state[8 + i]) ^ gmul(R[j][3], state[12 + i]);
		}
		for(j = 0; j < 4; j++)
			state[4 * j + i] = a[j];	
	}

}

/*
 *This function decryptes data
 *for first 9 rounds InvMixColumn is done along with InvSubBtyes, InvRowshift and AddRoundkey
 *but for last round InvMixcolumn is not done
 *First 10th roundkey is added before any round
 *and then for every round 9th, 8th, ... is added respectively 
 */

void AntiCipher(char *encry, char *orig, uint8_t *word) {
	uint8_t state[16], i, j, r;

	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			state[4 * i + j] = encry[4 * j + i];
	}

	AddRoundKey(state, word, Nr);

	for(r = Nr -1; r > 0; r--) {
		InvRowShift(state);
		InvSubByte(state);		
		AddRoundKey(state, word, r);
		InvMixColumn(state);
	}

	InvRowShift(state);
	InvSubByte(state);
	AddRoundKey(state, word, 0);
	/*Save state[16] to orig[]*/
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			orig[4 * j + i] = state[4 * i + j];
	}
}

int main(int argc, char *argv[]) {
	uint8_t *word;
	char *orig, *encry, c; 
	uint8_t i, x, j, flag = 1, n;
	FILE *fp1, *fp2;

	if((argc != 4) || (argc == 2 && !strcmp(argv[1], "-h"))) {
		printf("for help:\n  ./project -h\n");
		printf("for encryption:\n  Usage: ./project -e <filename1> <filename2>\n");
		printf("    filename1: file to be encrypted\n    filename2: encrypted file\n");
		printf("for decryption:\n  Usage: ./project -d <filename1> <filename2>\n");
		printf("    filename1: file to be decrypted\n    filename2: decrypted file\n");
		return 0;
	}

	/*
	 *128 bit key used for encryption and decryption
	 */
	uint8_t key[16] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f};
	
	/*
	 *w is array of words
	 *each word consist of 4 Bytes
	 *total words = (10 + 1) * 4
	 */
	word = malloc(4 * (Nr + 1) * sizeof(int) * 4);
	orig = (char*)malloc(sizeof(char) * 16);
	encry = (char*)malloc(sizeof(char) * 16);

	/*
	 *Generation of round keys
	 */
	RoundKey(key, word);
	
	if(!strcmp(argv[1], "-e")) {
		fp1 = fopen(argv[2], "r");
		fp2 = fopen(argv[3], "w");
		if(!fp1) {
			printf("Open Failed\n");
			return 0;
		}
		do {
			for(i = 0; i < 16; i++) {
				if((x = fscanf(fp1, "%c", &c) != EOF)) {
					orig[i] = c;
				}
				else {
					c = (16 - i) + '0';
					for(j = i; j < 16; j++) {
						orig[j] = c;
					}
					flag = 0;
					break;
				}
			}
			Cipher(orig, encry, word);
			for(i = 0; i < 16; i++) {
				fprintf(fp2, "%c", encry[i]);
			}
		} while(x);
		if(flag) {
			for(i = 0; i < 16; i++)
				orig[i] = '0';
			Cipher(orig, encry, word);
			for(i = 0; i < 16; i++) {
				fprintf(fp2, "%c", encry[i]);
			}
		}
		free(word);
		free(orig);
		free(encry);
		fclose(fp1);
		fclose(fp2);
		return 0;

	}

	else if(!strcmp(argv[1], "-d")) {
		fp1 = fopen(argv[2], "r");
		fp2 = fopen(argv[3], "w");

		if(!fp1) {
			printf("Open Failed\n");
			return 0;
		}

		while(1) {
			for(i = 0; i < 16; i++) {
				if((x = fscanf(fp1, "%c", &c) != EOF)) {
					encry[i] = c;
				}
			}
			if((x = fscanf(fp1, "%c", &c) == EOF)) {
				AntiCipher(encry, orig, word);				
				n = orig[15] - '0';
				
				for(i = 0; i < (16 - n); i++) {
					fprintf(fp2, "%c", orig[i]);
				}
				break;
			}
			else {
				fseek(fp1, -1, SEEK_CUR);
				AntiCipher(encry, orig, word);
				for(i = 0; i < 16; i++) {
					fprintf(fp2, "%c", orig[i]);
				}
			}
		}
		
		free(word);
		free(orig);
		free(encry);
		fclose(fp1);
		fclose(fp2);
		return 0;
	}
	else {
		printf("for help:\n  ./project -h\n");
		printf("for encryption:\n  Usage: ./project -e <filename1> <filename2>\n");
		printf("    filename1: file to be encrypted\n    filename2: encrypted file\n");
		printf("for decryption:\n  Usage: ./project -d <filename1> <filename2>\n");
		printf("    filename1: file to be decrypted\n    filename2: decrypted file\n");
		return 0;

	}
}
