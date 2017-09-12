// Defines
#define KVS_BUCKETS  16
#define VALSIZE     128
#define TAGSIZE      16
#define KEYSIZE      32
 
// Data structures
struct authval {
  unsigned char value[VALSIZE];
  unsigned char tag[TAGSIZE]; 
};

struct kvpair {
  unsigned char key[KEYSIZE];
  struct authval *av;
};

struct kv_list_entry {
  struct kvpair *entry;
  struct kv_list_entry *next;
};

// Global key-value store
extern struct kv_list_entry *kvs[KVS_BUCKETS]; 

// API
extern int kvs_init( char *filepath );
extern int kvs_auth_set( unsigned char *key, unsigned char *val, unsigned char *tag );
extern int kvs_auth_get( unsigned char *key, unsigned char **val, unsigned char **tag );



