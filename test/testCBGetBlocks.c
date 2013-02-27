//
//  testCBGetBlocks.c
//  cbitcoin
//
//  Created by Matthew Mitchell on 12/07/2012.
//  Copyright (c) 2012 Matthew Mitchell
//  
//  This file is part of cbitcoin. It is subject to the license terms
//  in the LICENSE file found in the top-level directory of this
//  distribution and at http://www.cbitcoin.com/license.html. No part of
//  cbitcoin, including this file, may be copied, modified, propagated,
//  or distributed except according to the terms contained in the
//  LICENSE file.

#include <stdio.h>
#include "CBGetBlocks.h"
#include <time.h>
#include "stdarg.h"

void CBLogError(char * format, ...);
void CBLogError(char * format, ...){
	va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
	printf("\n");
}

int main(){
	unsigned int s = (unsigned int)time(NULL);
	s = 1337544566;
	printf("Session = %ui\n", s);
	srand(s);
	// Test deserialisation
	uint8_t data[133] = {
		0x01, 0x00, 0x00, 0x00, // Version 1
		0x03, // 3 Hashes
		0xFB, 0x30, 0xB1, 0x9B, 0x3A, 0x0F, 0x82, 0x4A, 0xF1, 0x2B, 0x6E, 0xA4, 0x72, 0xBA, 0x9B, 0x3A, 0x67, 0xBA, 0xF2, 0xD8, 0x2E, 0x18, 0x06, 0x9D, 0x4A, 0x1B, 0x54, 0xA3, 0xD8, 0x9C, 0x43, 0xCF, // Hash 1
		0xFA, 0x50, 0x91, 0x9B, 0xEA, 0x9F, 0x72, 0x40, 0xA1, 0x25, 0xEE, 0x24, 0xB2, 0xBF, 0x7B, 0xAA, 0x27, 0x0A, 0xC2, 0xE8, 0x1E, 0x38, 0xF6, 0xED, 0x49, 0x4B, 0xE4, 0x63, 0x28, 0x7C, 0xC3, 0xAF, // Hash 2
		0xC8, 0x57, 0xA1, 0xFB, 0xCA, 0x8F, 0x22, 0x4B, 0x21, 0xB5, 0xFE, 0x94, 0x22, 0xB0, 0x7C, 0xBA, 0x87, 0x2A, 0xB2, 0xF8, 0xCE, 0x39, 0x56, 0xBD, 0x99, 0x4A, 0x44, 0x23, 0x2F, 0x8C, 0xA3, 0xFF, // Hash 3
		0xE8, 0x47, 0xA9, 0xBB, 0xD8, 0x4F, 0x72, 0x9B, 0x11, 0xB5, 0xFC, 0x96, 0x42, 0xE0, 0x9C, 0xBA, 0xA7, 0xF9, 0xE2, 0xFD, 0xC8, 0x49, 0xB6, 0xDD, 0x49, 0x8A, 0xE4, 0xA3, 0x3F, 0x0C, 0x23, 0x1F, // stopAtHash
	};
	CBByteArray * bytes = CBNewByteArrayWithDataCopy(data, 133);
	CBGetBlocks * getBlocks = CBNewGetBlocksFromData(bytes);
	if(CBGetBlocksDeserialise(getBlocks) != 133){
		printf("DESERIALISATION LEN FAIL\n");
		return 1;
	}
	if (getBlocks->chainDescriptor->hashNum != 3) {
		printf("DESERIALISATION NUM FAIL\n");
		return 1;
	}
	if (memcmp(CBByteArrayGetData(getBlocks->chainDescriptor->hashes[0]), (uint8_t []){0xFB, 0x30, 0xB1, 0x9B, 0x3A, 0x0F, 0x82, 0x4A, 0xF1, 0x2B, 0x6E, 0xA4, 0x72, 0xBA, 0x9B, 0x3A, 0x67, 0xBA, 0xF2, 0xD8, 0x2E, 0x18, 0x06, 0x9D, 0x4A, 0x1B, 0x54, 0xA3, 0xD8, 0x9C, 0x43, 0xCF}, 32)) {
		printf("DESERIALISATION FIRST HASH FAIL\n0x");
		uint8_t * d = CBByteArrayGetData(getBlocks->chainDescriptor->hashes[0]);
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		printf("\n!=\n0x");
		d = (uint8_t []){0xFB, 0x30, 0xB1, 0x9B, 0x3A, 0x0F, 0x82, 0x4A, 0xF1, 0x2B, 0x6E, 0xA4, 0x72, 0xBA, 0x9B, 0x3A, 0x67, 0xBA, 0xF2, 0xD8, 0x2E, 0x18, 0x06, 0x9D, 0x4A, 0x1B, 0x54, 0xA3, 0xD8, 0x9C, 0x43, 0xCF};
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		return 1;
	}
	if (memcmp(CBByteArrayGetData(getBlocks->chainDescriptor->hashes[1]), (uint8_t []){0xFA, 0x50, 0x91, 0x9B, 0xEA, 0x9F, 0x72, 0x40, 0xA1, 0x25, 0xEE, 0x24, 0xB2, 0xBF, 0x7B, 0xAA, 0x27, 0x0A, 0xC2, 0xE8, 0x1E, 0x38, 0xF6, 0xED, 0x49, 0x4B, 0xE4, 0x63, 0x28, 0x7C, 0xC3, 0xAF}, 32)) {
		printf("DESERIALISATION SECOND HASH FAIL\n0x");
		uint8_t * d = CBByteArrayGetData(getBlocks->chainDescriptor->hashes[0]);
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		printf("\n!=\n0x");
		d = (uint8_t []){0xFA, 0x50, 0x91, 0x9B, 0xEA, 0x9F, 0x72, 0x40, 0xA1, 0x25, 0xEE, 0x24, 0xB2, 0xBF, 0x7B, 0xAA, 0x27, 0x0A, 0xC2, 0xE8, 0x1E, 0x38, 0xF6, 0xED, 0x49, 0x4B, 0xE4, 0x63, 0x28, 0x7C, 0xC3, 0xAF};
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		return 1;
	}
	if (memcmp(CBByteArrayGetData(getBlocks->chainDescriptor->hashes[2]), (uint8_t []){0xC8, 0x57, 0xA1, 0xFB, 0xCA, 0x8F, 0x22, 0x4B, 0x21, 0xB5, 0xFE, 0x94, 0x22, 0xB0, 0x7C, 0xBA, 0x87, 0x2A, 0xB2, 0xF8, 0xCE, 0x39, 0x56, 0xBD, 0x99, 0x4A, 0x44, 0x23, 0x2F, 0x8C, 0xA3, 0xFF}, 32)) {
		printf("DESERIALISATION THIRD HASH FAIL\n0x");
		uint8_t * d = CBByteArrayGetData(getBlocks->chainDescriptor->hashes[0]);
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		printf("\n!=\n0x");
		d = (uint8_t []){0xC8, 0x57, 0xA1, 0xFB, 0xCA, 0x8F, 0x22, 0x4B, 0x21, 0xB5, 0xFE, 0x94, 0x22, 0xB0, 0x7C, 0xBA, 0x87, 0x2A, 0xB2, 0xF8, 0xCE, 0x39, 0x56, 0xBD, 0x99, 0x4A, 0x44, 0x23, 0x2F, 0x8C, 0xA3, 0xFF};
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		return 1;
	}
	if (memcmp(CBByteArrayGetData(getBlocks->stopAtHash), (uint8_t []){0xE8, 0x47, 0xA9, 0xBB, 0xD8, 0x4F, 0x72, 0x9B, 0x11, 0xB5, 0xFC, 0x96, 0x42, 0xE0, 0x9C, 0xBA, 0xA7, 0xF9, 0xE2, 0xFD, 0xC8, 0x49, 0xB6, 0xDD, 0x49, 0x8A, 0xE4, 0xA3, 0x3F, 0x0C, 0x23, 0x1F}, 32)) {
		printf("DESERIALISATION STOP AT HASH FAIL\n0x");
		uint8_t * d = CBByteArrayGetData(getBlocks->stopAtHash);
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		printf("\n!=\n0x");
		d = (uint8_t []){0xE8, 0x47, 0xA9, 0xBB, 0xD8, 0x4F, 0x72, 0x9B, 0x11, 0xB5, 0xFC, 0x96, 0x42, 0xE0, 0x9C, 0xBA, 0xA7, 0xF9, 0xE2, 0xFD, 0xC8, 0x49, 0xB6, 0xDD, 0x49, 0x8A, 0xE4, 0xA3, 0x3F, 0x0C, 0x23, 0x1F};
		for (int x = 0; x < 32; x++) {
			printf("%.2X", d[x]);
		}
		return 1;
	}
	// Test serialisation with timestamps
	memset(CBByteArrayGetData(bytes), 0, 133);
	CBReleaseObject(getBlocks->chainDescriptor->hashes[0]);
	getBlocks->chainDescriptor->hashes[0] = CBNewByteArrayWithDataCopy((uint8_t []){0xFB, 0x30, 0xB1, 0x9B, 0x3A, 0x0F, 0x82, 0x4A, 0xF1, 0x2B, 0x6E, 0xA4, 0x72, 0xBA, 0x9B, 0x3A, 0x67, 0xBA, 0xF2, 0xD8, 0x2E, 0x18, 0x06, 0x9D, 0x4A, 0x1B, 0x54, 0xA3, 0xD8, 0x9C, 0x43, 0xCF}, 32);
	CBReleaseObject(getBlocks->chainDescriptor->hashes[1]);
	getBlocks->chainDescriptor->hashes[1] = CBNewByteArrayWithDataCopy((uint8_t []){0xFA, 0x50, 0x91, 0x9B, 0xEA, 0x9F, 0x72, 0x40, 0xA1, 0x25, 0xEE, 0x24, 0xB2, 0xBF, 0x7B, 0xAA, 0x27, 0x0A, 0xC2, 0xE8, 0x1E, 0x38, 0xF6, 0xED, 0x49, 0x4B, 0xE4, 0x63, 0x28, 0x7C, 0xC3, 0xAF}, 32);
	CBReleaseObject(getBlocks->chainDescriptor->hashes[2]);
	getBlocks->chainDescriptor->hashes[2] = CBNewByteArrayWithDataCopy((uint8_t []){0xC8, 0x57, 0xA1, 0xFB, 0xCA, 0x8F, 0x22, 0x4B, 0x21, 0xB5, 0xFE, 0x94, 0x22, 0xB0, 0x7C, 0xBA, 0x87, 0x2A, 0xB2, 0xF8, 0xCE, 0x39, 0x56, 0xBD, 0x99, 0x4A, 0x44, 0x23, 0x2F, 0x8C, 0xA3, 0xFF}, 32);
	CBReleaseObject(getBlocks->stopAtHash);
	getBlocks->stopAtHash = CBNewByteArrayWithDataCopy((uint8_t []){0xE8, 0x47, 0xA9, 0xBB, 0xD8, 0x4F, 0x72, 0x9B, 0x11, 0xB5, 0xFC, 0x96, 0x42, 0xE0, 0x9C, 0xBA, 0xA7, 0xF9, 0xE2, 0xFD, 0xC8, 0x49, 0xB6, 0xDD, 0x49, 0x8A, 0xE4, 0xA3, 0x3F, 0x0C, 0x23, 0x1F}, 32);
	if (CBGetBlocksSerialise(getBlocks, true) != 133) {
		printf("SERIALISATION LEN FAIL\n");
		return 1;
	}
	if (memcmp(data, CBByteArrayGetData(bytes), 133)) {
		printf("SERIALISATION FAIL\n0x");
		uint8_t * d = CBByteArrayGetData(bytes);
		for (int x = 0; x < 133; x++) {
			printf("%.2X", d[x]);
		}
		printf("\n!=\n0x");
		for (int x = 0; x < 133; x++) {
			printf("%.2X", data[x]);
		}
		return 1;
	}
	CBReleaseObject(getBlocks);
	CBReleaseObject(bytes);
	return 0;
}
