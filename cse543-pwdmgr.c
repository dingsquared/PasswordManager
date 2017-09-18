#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
//#include <openssl/x509.h>
//#include <openssl/rand.h>
#include "cse543-kvs.h"
#include "cse543-cracker.h"
#include "cse543-ssl.h"

/* Defines */
#define ENC_KEY_LEN       32
#define MASTER_PASSWD_LEN 16
#define MIN_GUESS_NUMBER  100000000  // means...  10^17 guesses?
#define MAX_DOMAIN       60
#define MAX_PASSWD       30
#define SEPARATOR_CHAR   ':'


/* Project APIs */
extern int make_key_from_master(char *master, unsigned char **enc_key,
				  unsigned char **hmac_key);
extern int obtain_strong_password(char *orig_passwd, char* crack_file, char **passwd,
			   size_t *pwdlen);
extern int upload_password(char *domain, size_t dlen, char *passwd, size_t plen,
			   unsigned char *enc_key, unsigned char *hmac_key );
extern size_t lookup_password(char *domain, size_t dlen, unsigned char **passwd, unsigned char *enc_key,
			      unsigned char *hmac_key);
extern int compute_hmac_key(char *input, size_t len, unsigned char **hmac, size_t *hlen,
			     unsigned char *hmac_key);
extern int kvs_dump(FILE *, unsigned char *enc_key);


int main(int argc, char *argv[])
{
  FILE *fp = stdin;  // default: replaced if input and lookup files are specified and replaced when kvs_dump is run
  int err;
  size_t pwdlen;
  char *passwd;
  unsigned char *passwd2;
  unsigned char *enc_key = (unsigned char *)malloc(32),
    *hmac_key = (unsigned char *)malloc(32);
  char input_domain[MAX_DOMAIN], input_passwd[MAX_PASSWD];
  char *rptr;

  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

  /* assert on argc */
  /* main password_file master_passwd crack_file */
  assert(( argc == 4 ) || ( argc == 6 ));

  /* initialize KVS from file */
  kvs_init( argv[1] );

  /* ... Do some crypto stuff here ... */
  /* Derive keys from master secret - from command line */
  /* A 256 bit key */
  /* 16 byte max from master password (argv[2]) - rest random salt */
  err = make_key_from_master( argv[2], &enc_key, &hmac_key );

	//printf("enc_key = %s\n", enc_key);
	//printf("hmac_key = %s\n", hmac_key);
  assert ( err == 0 );

  /* Obtain passwords and verify strength of password against Markov Cracker */
  // obtain_password (function) - collect domain and password and check/improve strength
  // in a while loop presumably
  printf("\n\n ==== Input some passwords for specified domains ==== \n");

  /* Open file for input requests, if present */
  if (argc == 6) {
    fp = fopen( argv[4], "r" );  // read input
    assert( fp != NULL );
  }

	char *line = NULL;
	size_t len;
	ssize_t read;

  while (1) {
    /* TASK 2: Obtain input values for domain-password pairs from user */
		#if 0
		if(argc == 4){ //read from command line
			printf("Input Domain: ");
			if ((read = getline(&line, &len, fp)) == -1) {
			  break;
			};

			if(read > MAX_DOMAIN){
				fprintf(stderr, "Domain name too long: abort\n");
				abort();
			}

			strncpy(input_domain, line, MAX_DOMAIN);
			free(line);
			line = 0;

	    printf("Password: ");
			if ((read = getline(&line, &len, fp)) == -1) {
			  fprintf(stderr, "Error reading input password: abort\n");
				abort();
			};

			if(read > MAX_PASSWD){
				fprintf(stderr, "Password too long: abort\n");
				abort();
			}

			strncpy(input_passwd, line, MAX_PASSWD);
			free(line);
			line = 0;

		}
		else { //read from file
			if ((read = getline(&line, &len, fp)) == -1) {
			  break;
			};
			if(read > MAX_DOMAIN){
				fprintf(stderr, "Domain name too long: abort\n");
				abort();
			}

			strncpy(input_domain, line, MAX_DOMAIN);
			printf("Domain: %s\n", input_domain);
			free(line);
			line = 0;

			if ((read = getline(&line, &len, fp)) == -1) {
			  fprintf(stderr, "Error reading input password: abort\n");
				abort();
			};

			if(read > MAX_PASSWD){
				fprintf(stderr, "Password too long: abort\n");
				abort();
			}



			strncpy(input_passwd, line, MAX_PASSWD);
		  printf("Password: %s\n", input_passwd);
			free(line);
			line = 0;
		}
    #endif

		if(argc == 4){ //read from command line
			printf("Input Domain: ");
			if (fgets(input_domain, MAX_DOMAIN, fp) == NULL)
			  break;

	    printf("Password: ");
			if (fgets(input_passwd, MAX_PASSWD, fp) == NULL) {
			  fprintf(stderr, "Error reading password: abort\n");
				abort();
			};
		}
		else { //read from file
			if (fgets(input_domain, MAX_DOMAIN, fp) == NULL)
			  break;
			printf("Domain: %s\n", input_domain);

			if (fgets(input_passwd, MAX_PASSWD, fp) == NULL) {
			  fprintf(stderr, "Error reading password: abort\n");
				abort();
			};

		  printf("Password: %s\n", input_passwd);
		}


    #if 1
    /* strengthen password relative to crack_file (argv[3]) */
    //err = obtain_strong_password( input_passwd, argv[3], &passwd, &pwdlen );
    //assert( err >= 0 );

    /* Upload encrypted and authenticated password into key-value store */
    /* Replace password if existing domain */
		passwd = input_passwd;
		pwdlen = strlen(passwd);
    printf("+++ Uploading domain-password pair: %s --> %s\n", input_domain, passwd);
    err = upload_password( input_domain, strlen(input_domain), passwd, pwdlen,  enc_key, hmac_key );
    fflush(stdout);
		#endif
  }

  if (argc == 6)
    fclose( fp );


  printf("\n\n ==== Now lookup passwords for specified domains ==== \n");

  /* Open file for lookup requests, if present */
  if (argc == 6) {
    fp = fopen( argv[5], "r" );  // read input
    assert( fp != NULL );
  }

  /* Get some passwords for domains - decrypt and "use" */
  while (1) {
    /* TASK 5: Obtain domain value to retrieve password from user */
    /* Lookup some domain's password */
    printf("\nLookup Domain: ");

		if (fgets(input_domain, MAX_DOMAIN, fp) == NULL)
			break;

    // retrieve password, tag for domain's HMAC value
    err = lookup_password( input_domain, strlen(input_domain), &passwd2, enc_key, hmac_key );

    // "use" password (print) if one is found
    if ( err > 0 ) {
      printf("\n*** Lookup password for domain: %s -> %s", input_domain, passwd2 );
      // free( passwd2 );  // CRASH, but not sure why different than above
    }
    else
      printf("\nPassword retrieval for domain %s failed: %d", input_domain, err );

    fflush(stdout);
  }

  if (argc == 6)
    fclose( fp );

	/*{
	  err = lookup_password( input_domain, strlen(input_domain), &passwd2, enc_key, hmac_key );
	  if ( err > 0 ) {
		  printf("\n*** Lookup password for domain: %s -> %s", input_domain, passwd2 );
		  // free( passwd2 );  // CRASH, but not sure why different than above
	  }
	  else
		  printf("\nPassword retrieval for domain %s failed: %d", input_domain, err );

	  fflush(stdout);
  }*/
  /* Debug print of passwords in the clear */
  err = kvs_dump( stdout, enc_key );

  /* At end, write KVS to file (stdout first) */
  fp = fopen( argv[1], "w+" );  // rewrite file
  assert( fp != NULL );
  err = kvs_dump( fp, NULL );
  fclose( fp );

  /* Other cleanup */
  // free hkey
  free( hmac_key );
  free( enc_key );

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use
     of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}


int make_key_from_master(char *master, unsigned char **enc_key, unsigned char **hmac_key)
{
  /* TASK 1: Make encryption and HMAC keys from master password */
  /* Both keys must be different and be derived from the master password
     such that no one who does not know the master password could guess
     the keys. */
	unsigned int len = strlen(master);
	digest_message(master, len, &(*enc_key), &len);
	assert(len==32);
	digest_message(*enc_key, len, &(*hmac_key), &len);
  assert(len==32);

  //digest_message()
  return 0;
}


int upload_password( char *domain, size_t dlen, char *passwd, size_t plen,
		     unsigned char *enc_key, unsigned char *hmac_key )
{
  int i = 0;
  unsigned char *pwdbuf = (unsigned char *)malloc(VALSIZE);
  unsigned char *ciphertext, *plaintext, *tag, *hmac;
  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"0123456789012345";
  int clen;
  size_t hlen;

  /* TASK 4: Protect the secrecy and integrity of the domain and password */
  /* (1) HMAC the domain value to produce the key of the key-value pair and
     (2) perform an authenticated encryption of the password and (3) store in
     key-value store. */

  /* (1) Compute the HMAC from the domain for the key value for KVS */
	//BIO_dump_fp(stdout, domain, dlen);
	//BIO_dump_fp(stdout, hmac_key, 16);

  if((hmac = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
	    handleErrors();
  hmac_message(domain, dlen, &hmac, &hlen, hmac_key);
  BIO_dump_fp(stdout, hmac, hlen);
  /* (2) Authenticated Encryption of Password */
	strncpy(pwdbuf, passwd, VALSIZE);
	ciphertext = (unsigned char *)malloc(VALSIZE);
	tag = (unsigned char *)malloc(TAGSIZE);
	printf("passwd = %s\n", passwd);
	printf("pwdbuf = %s\n", pwdbuf);
	// padding
	for (size_t i = plen; i < VALSIZE; i++) {
		pwdbuf[i] = '\0';
	}
  encrypt(pwdbuf, VALSIZE, NULL, 0, enc_key, iv, ciphertext, tag);

#if 0
  /* Do something useful with the ciphertext here */
  /* print ciphertext and tag */
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, clen);

  printf("Tag is:\n");
  BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);

  /* (opt) decrypt to make sure things are working correctly */
  /* decrypt */
  plen = decrypt(ciphertext, clen, (unsigned char *) NULL, 0,
		 tag, enc_key, iv, plaintext);
  assert( plen >= 0 );

  /* Add a NULL terminator. We are expecting printable text */
  plaintext[plen] = '\0';

  /* Show the decrypted text */
  // Skip prefix, but will remove prefix
  printf("Decrypted text is:\n");
  for ( i = 0 ; plaintext[i] != SEPARATOR_CHAR; i++ );
  printf("Text: %s\n", plaintext+i+1 );
#endif


  /* (3) Set the hmac (domain) and encrypted (password with tag) in KVS */
  kvs_auth_set( hmac, ciphertext, tag );

  return 0;
}


size_t lookup_password( char *domain, size_t dlen, unsigned char **passwd, unsigned char *enc_key,
		     unsigned char *hmac_key )
{
  int i = 0;
  unsigned char *ciphertext, *tag, *hmac;
  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"0123456789012345";
  int plen, err;
  size_t hlen;

  /* TASK 6: Retrieve the password from the key-value store */
  /* (1) Compute "key" for password entry in key-value store by
     computing HMAC of the domain and (2) then retrieve the encrypted
     password from the key-value store and (3) decrypt the password,
     returning the password length in plen */


  /* (1) Compute the HMAC from the domain for the key value for KVS */
	if((hmac = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
	    handleErrors();
  hmac_message(domain, dlen, &hmac, &hlen, hmac_key);

  /* (2) Lookup key in key-value store */
  ciphertext = (unsigned char *)malloc(VALSIZE);
  tag = (unsigned char *)malloc(TAGSIZE);
  err = kvs_auth_get(hmac, &ciphertext, &tag);
  if ( err != 0 ) return -1;  // Not found

  /* (3) Decrypt password */
	unsigned char* plaintext = (unsigned char *)malloc(VALSIZE);
  decrypt(ciphertext, VALSIZE, NULL, 0, tag, enc_key, iv, plaintext);
	*passwd = plaintext;
	plen = strlen(plaintext);
  return plen;
  //return plen;
}


int obtain_strong_password(char *orig_passwd, char* crack_file, char **passwd,
			   size_t *pwdlen)
{
  double guessNumber;
  int i = 0, ct = 0;

  // copy original password to output password buffer
  *pwdlen = strlen( orig_passwd );
  *passwd = (char *)malloc( *pwdlen+1 );
  strncpy( *passwd, orig_passwd, *pwdlen );
  (*passwd)[*pwdlen] = '\0';

  // check password
  guessNumber = get_markov_guess_number( *passwd, *pwdlen, crack_file );
  while ( guessNumber < MIN_GUESS_NUMBER ) {
    /* TASK 3: Strengthen passwords that fail minimum guess threshold */
    /* Goal is to use the minimal number of iterations to produce a
       satisfactory password */

    // check password again
    guessNumber = get_markov_guess_number( *passwd, *pwdlen, crack_file );
    ct++;
  }

  return 0;
}

// TJ: Shall I remove this function ...
int compute_hmac_key( char *input, size_t len, unsigned char **hmac, size_t *hlen,
		      unsigned char *hmac_key )
{
  int i = 0;
  unsigned char *buf = (unsigned char *)malloc(KEYSIZE);
  int err;

  *hlen = KEYSIZE;

  /* check lengths */
  assert(len <= KEYSIZE);

  /* fill dombuf with domain and spaces */
  memcpy( buf, input, len );
  for ( i = len; i < KEYSIZE; i++ ) {
    buf[i] = '\0';
  }

  /* (1) generate HMAC (key in key-value pair) for domain */
  *hmac = (unsigned char *)malloc(*hlen);
  err = hmac_message( buf, KEYSIZE, hmac, hlen, hmac_key );
  assert( err >= 0 );

#if 0
  printf("Domain hmac is:\n");
  BIO_dump_fp (stdout, (const char *)*hmac, *hlen);
#endif

  return 0;
}


int kvs_dump(FILE *fptr, unsigned char *enc_key)
{
    int i, plen;
    struct kv_list_entry *kvle;
    struct authval *av;
    struct kvpair *kvp;
    unsigned char *key;

    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char *plaintext;

    for (i = 0; i < KVS_BUCKETS; i++) {
      kvle = kvs[i];

      while ( kvle != NULL ) {
	kvp = kvle->entry;

	av = kvp->av;
	key = kvp->key;

	if (enc_key) {  /* Dump decrypted value */
#if 0
	  BIO_dump_fp (fptr, (const char *)key, KEYSIZE);  // Dump key
#endif
	  /* decrypt */
	  plaintext = (unsigned char *)malloc(VALSIZE);
	  plen = decrypt(av->value, VALSIZE, (unsigned char *) NULL, 0,
			 av->tag, enc_key, iv, plaintext);
	  assert( plen >= 0 );

	  /* Show the decrypted text */
#if 0
	  printf("Password: %s\n", plaintext);
	  BIO_dump_fp (fptr, (const char *)plaintext, plen);
	  BIO_dump_fp (fptr, (const char *)av->tag, TAGSIZE);  // Dump tag
	  BIO_dump_fp (fptr, (const char *)"----", 4);         // Dump separator
#endif
	  free(plaintext);
	}
	else {          /* Dump encrypted value */
	  fwrite((const char *)key, 1, KEYSIZE, fptr);
	  fwrite((const char *)av->value, 1, VALSIZE, fptr);
	  fwrite((const char *)av->tag, 1, TAGSIZE, fptr);
	  fwrite((const char *)"----", 1, 4, fptr);
	}


	// Next entry
	kvle = kvle->next;
      }
    }
    return 0;
}
