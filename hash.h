/*
**  Hash routines
**    
*/

#include <stddef.h>
#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#define HASH_SUPPORTS_DELETE

typedef struct HashTableElement
{
	struct HashTableElement *pPrev;
	struct HashTableElement *pNext;
	char *pData;
}HashTable_Element;

typedef struct  HashTables
{
	//unsigned Hash(const char*szSearchFor);
	unsigned nBuckets;
	unsigned uDatumSize;
	unsigned uCount;
	struct HashTableElement **ppChain;
}HashTable;

#endif
