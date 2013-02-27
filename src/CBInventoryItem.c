//
//  CBInventoryItem.c
//  cbitcoin
//
//  Created by Matthew Mitchell on 10/07/2012.
//  Copyright (c) 2012 Matthew Mitchell
//  
//  This file is part of cbitcoin. It is subject to the license terms
//  in the LICENSE file found in the top-level directory of this
//  distribution and at http://www.cbitcoin.com/license.html. No part of
//  cbitcoin, including this file, may be copied, modified, propagated,
//  or distributed except according to the terms contained in the
//  LICENSE file.

//  SEE HEADER FILE FOR DOCUMENTATION 

#include "CBInventoryItem.h"

//  Constructors

CBInventoryItem * CBNewInventoryItem(CBInventoryItemType type, CBByteArray * hash){
	CBInventoryItem * self = malloc(sizeof(*self));
	if (NOT self) {
		CBLogError("Cannot allocate %i bytes of memory in CBNewInventoryItem\n", sizeof(*self));
		return NULL;
	}
	CBGetObject(self)->free = CBFreeInventoryItem;
	if(CBInitInventoryItem(self, type, hash))
		return self;
	free(self);
	return NULL;
}
CBInventoryItem * CBNewInventoryItemFromData(CBByteArray * data){
	CBInventoryItem * self = malloc(sizeof(*self));
	if (NOT self) {
		CBLogError("Cannot allocate %i bytes of memory in CBNewInventoryItemFromData\n", sizeof(*self));
		return NULL;
	}
	CBGetObject(self)->free = CBFreeInventoryItem;
	if(CBInitInventoryItemFromData(self, data))
		return self;
	free(self);
	return NULL;
}

//  Object Getter

CBInventoryItem * CBGetInventoryItem(void * self){
	return self;
}

//  Initialisers

bool CBInitInventoryItem(CBInventoryItem * self, CBInventoryItemType type, CBByteArray * hash){
	self->type = type;
	self->hash = hash;
	CBRetainObject(hash);
	if (NOT CBInitMessageByObject(CBGetMessage(self)))
		return false;
	return true;
}
bool CBInitInventoryItemFromData(CBInventoryItem * self, CBByteArray * data){
	self->hash = NULL;
	if (NOT CBInitMessageByData(CBGetMessage(self), data))
		return false;
	return true;
}

//  Destructor

void CBDestroyInventoryItem(void * vself){
	CBInventoryItem * self = vself;
	CBReleaseObject(self->hash);
	CBDestroyMessage(self);
}
void CBFreeInventoryItem(void * self){
	CBDestroyInventoryItem(self);
	free(self);
}

//  Functions

uint32_t CBInventoryItemDeserialise(CBInventoryItem * self){
	CBByteArray * bytes = CBGetMessage(self)->bytes;
	if (NOT bytes) {
		CBLogError("Attempting to deserialise a CBInventoryItem with no bytes.");
		return 0;
	}
	if (bytes->length < 36) {
		CBLogError("Attempting to deserialise a CBInventoryItem with less than 36 bytes.");
		return 0;
	}
	self->type = CBByteArrayReadInt32(bytes, 0);
	self->hash = CBByteArraySubReference(bytes, 4, 32);
	if (NOT self->hash)
		return 0;
	return 36;
}
uint32_t CBInventoryItemSerialise(CBInventoryItem * self){
	CBByteArray * bytes = CBGetMessage(self)->bytes;
	if (NOT bytes) {
		CBLogError("Attempting to serialise a CBInventoryItem with no bytes.");
		return 0;
	}
	if (bytes->length < 36) {
		CBLogError("Attempting to serialise a CBInventoryItem with less than 36 bytes.");
		return 0;
	}
	CBByteArraySetInt32(bytes, 0, self->type);
	CBByteArrayCopyByteArray(bytes, 4, self->hash);
	CBByteArrayChangeReference(self->hash, bytes, 4);
	bytes->length = 36;
	CBGetMessage(self)->serialised = true;
	return 36;
}

