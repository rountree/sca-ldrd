/* sym.c
 *
 * Original source copied from
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>         // calloc(3)
#include <assert.h>         // assert(3)
#include <stdio.h>          // printf(3)
#include <sys/time.h>       // gettimeofday(2)

#define PLAINTEXT_BUF_SZ (INT_MAX - 4096)   // Assumes sizeof(int)==4
#define CRYPTTEXT_BUF_SZ (INT_MAX       )
#define NUM_KEYS (32LL)        // NUM_KEYS * KEY_SZ_IN_BYTES must be <= INT_MAX
#define KEY_SZ_IN_BYTES (16LL)
#define NUM_NONCES (NUM_KEYS)
#define NONCE_SZ_IN_BYTES (8LL)

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
void print_elapsed( struct timeval *start, struct timeval *stop, char const * const file, int line, char const * const msg );

void print_elapsed( struct timeval *start, struct timeval *stop, char const * const file, int line, char const * const msg ){
    printf("%s:%d %10.8lf %s\n",
            file, line,
            (stop->tv_sec - start->tv_sec) + (stop->tv_usec - start->tv_usec)/1000000.0,
            msg);
}

int main (void)
{
    struct timeval start, stop;
    /*
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    */

    // Set up a pile of random keys.
    assert( NUM_KEYS * KEY_SZ_IN_BYTES < INT_MAX );
    gettimeofday( &start, NULL );
    unsigned char *keys = calloc( NUM_KEYS, KEY_SZ_IN_BYTES );
    assert(keys);
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( NUM_KEYS, KEY_SZ_IN_BYTES )" );
    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( keys, NUM_KEYS * KEY_SZ_IN_BYTES ) );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( keys, NUM_KEYS * KEY_SZ_IN_BYTES )" );

    // Set up a pile of random nonces
    assert( NUM_NONCES * NONCE_SZ_IN_BYTES < INT_MAX );
    gettimeofday( &start, NULL );
    unsigned char *ivs = calloc( NUM_NONCES, NONCE_SZ_IN_BYTES );
    assert(ivs);
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( NUM_NONCES, NONCE_SZ_IN_BYTES )" );
    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( ivs, NUM_NONCES * NONCE_SZ_IN_BYTES ) );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( ivs, NUM_NONCES * NONCE_SZ_IN_BYTES )" );

    // Set up long, random, plaintext message.
    gettimeofday( &start, NULL );
    unsigned char *plaintext = calloc( PLAINTEXT_BUF_SZ, 1 );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( PLAINTEXT_BUF_SZ, 1 )" );
    assert( plaintext );
    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( plaintext, PLAINTEXT_BUF_SZ ) );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( plaintext, PLAINTEXT_BUF_SZ )" );

    // Set up (longer) buffer for encrypted text.
    gettimeofday( &start, NULL );
    unsigned char *ciphertext = calloc( CRYPTTEXT_BUF_SZ, 1 );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( CRYPTTEXT_BUF_SZ, 1 )" );
    assert( ciphertext );

    // Do the encryption
    int ciphertext_len;
    for( size_t i=0; i<NUM_KEYS; i++ ){
        gettimeofday( &start, NULL );
        ciphertext_len = encrypt (plaintext, PLAINTEXT_BUF_SZ, &keys[i], &ivs[i], ciphertext);
        gettimeofday( &stop, NULL );
        print_elapsed( &start, &stop, __FILE__, __LINE__, "encrypt( ... )" );
    }

    // Report out some details
    printf(" %d bytes of plaintext, %d bytes encrypted buffer, %d bytes encrypted text, %d bytes of unused buffer.\n",
            PLAINTEXT_BUF_SZ,  CRYPTTEXT_BUF_SZ, ciphertext_len, CRYPTTEXT_BUF_SZ - ciphertext_len );

    return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    struct timeval start, stop;
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    // Initialize context.  Caution:  key and iv vary per algorithm
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptInit_ex( ... )" );

    // One-shot encryption
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptUpdate( ... )" );
    ciphertext_len = len;

    // Finalize
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptFinal_ex( ... )" );
    ciphertext_len += len;

    // Clean up 
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
