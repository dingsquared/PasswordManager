#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include "cse543-kvs.h"
#include "cse543-util.h"

// Global Key-Value Store
struct kv_list_entry *kvs[KVS_BUCKETS]; 

// Internal functions
extern struct kv_list_entry *kvs_match( unsigned char *key );


int kvs_init( char *filepath )
{
  int i, err;
  unsigned char *buf, *orig_buf;
  size_t bufsize;
  size_t bytes_left = 0;

  // initialize buckets 
  for (i = 0; i < KVS_BUCKETS; i++) {
    kvs[i] = (struct kv_list_entry *) NULL;
  }

  // Get buf for current file contents
  bufsize = buffer_from_file( filepath, &buf );
  assert( bufsize >= 0 ); 

  // add entries from buf into KVS
  if ( bufsize > 0 ) {
    unsigned int entrysz = (KEYSIZE+VALSIZE+TAGSIZE+4);    
    bytes_left = bufsize; 
    orig_buf = buf;

    while ( bytes_left >= entrysz ) {  
      err = kvs_auth_set(buf, buf+KEYSIZE, buf+KEYSIZE+VALSIZE);  
      bytes_left -= entrysz;
      buf += entrysz;
    }
    free( orig_buf );
  }
  assert(bytes_left == 0);    

  return 0;
}


int kvs_auth_set(unsigned char *key, unsigned char *val, unsigned char *tag)
{
  struct authval *av;
  struct kvpair *kvp;
  struct kv_list_entry *kvle, *head;

  assert( key && val && tag );

  /* lookup existing key */
  kvle = kvs_match( key );
  if ( kvle ) {
    // if found, replace value and tag 
    memcpy( kvle->entry->av->value, val, VALSIZE );
    memcpy( kvle->entry->av->tag, tag, TAGSIZE ); 
    return 0;
  }

  /* make KVE */
  kvp = (struct kvpair *)malloc(sizeof(struct kvpair));
  assert( kvp != 0 );
  memcpy( kvp->key, key, KEYSIZE );

  av = (struct authval *)malloc(sizeof(struct authval));
  assert( av != 0 );
  kvp->av = av;
  memcpy( av->value, val, VALSIZE );
  memcpy( av->tag, tag, TAGSIZE ); 

  /* make list entry */
  kvle = (struct kv_list_entry *)malloc(sizeof(struct kv_list_entry));
  assert( kvle != 0 );
  kvle->entry = kvp;

  /* put in KVS */
  // use lower 4 bits of last byte in key as bucket id 
  unsigned int bucket = 0xF & (key[KEYSIZE-1]); 
  head = kvs[bucket];
  
  if ( head == NULL ) {
    kvs[bucket] = kvle;
    kvle->next = (struct kv_list_entry *)NULL;
  }
  else {
    kvs[bucket] = kvle;
    kvle->next = head;
  }

  return 0;
}


int kvs_auth_get(unsigned char *key, unsigned char **val, unsigned char **tag)
{
  struct kv_list_entry *kvle;

  assert( key != 0 );

  kvle = kvs_match( key );
  if ( kvle ) {
    //    memcpy( *val, kvle->entry->av->value, VALSIZE );
    *val = kvle->entry->av->value;
    //    memcpy( *tag, kvle->entry->av->tag, TAGSIZE );
    *tag = kvle->entry->av->tag;
    return 0;
  }
  
  return 1;
}


struct kv_list_entry *kvs_match( unsigned char *key )
{
  unsigned int bucket;
  struct kv_list_entry *kvle;

  // use lower 4 bits of last byte in key as bucket id 
  bucket = 0xF & (key[KEYSIZE-1]); 
  kvle = kvs[bucket];

  while( kvle != NULL ) {
    struct kv_list_entry *next = kvle->next;
    if ( memcmp( key, kvle->entry->key, KEYSIZE ) == 0 ) {
      return kvle;
    }
    kvle = next;
  }

  return (struct kv_list_entry *)NULL;
}

#if 0
// Utility
int buffer_from_file(char *filepath, unsigned char **buf)
{
  int err;
  struct stat *statbuf;
  FILE *fptr;
  size_t filesize;

  statbuf = (struct stat *)malloc(sizeof(struct stat));
  assert( statbuf != NULL );

  err = stat( filepath, statbuf );

  /* if file does not exist ... */
  if ( err != 0 ) {
    filesize = 0;
  }
  /* else if file exists */
  else {
    /* Get file size */
    filesize = statbuf->st_size;
    assert( filesize > 0 );

    /* Read file data into buf */
    *buf = (unsigned char *)malloc(filesize); 
    assert( *buf != NULL );
  
    fptr = fopen( filepath, "r" );
    if ( fptr != NULL ) {
      err = fread( *buf, 1, filesize, fptr );
      assert( err == filesize ); 
    }
    fclose( fptr );
  }

  free( statbuf );
  
  return filesize;
}
#endif
