/* sym.c
 *
 * Original source copied from
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/time.h>       // gettimeofday(2)
#include <sys/ioctl.h>      // ioctl(2)
#include <sys/types.h>      // open(2)
#include <sys/stat.h>       // "
#include <fcntl.h>          // "
#include <unistd.h>         // sleep(3)
#include <stdlib.h>         // calloc(3), exit(3)
#include <assert.h>         // assert(3)
#include <stdio.h>          // printf(3)
#include <stdint.h>         // uint64_t
#include <inttypes.h>       // PRIu64
#include "../../msr-safe/msr_safe.h"    // msr_batch_array, msr_batch_op, X86_IOC_MSR_BATCH

#define PLAINTEXT_BUF_SZ (INT_MAX - 4096)   // Assumes sizeof(int)==4
#define CRYPTTEXT_BUF_SZ (INT_MAX       )
#define NUM_KEYS (32LL)        // NUM_KEYS * KEY_SZ_IN_BYTES must be <= INT_MAX
#define KEY_SZ_IN_BYTES (16LL)
#define NUM_NONCES (NUM_KEYS)
#define NONCE_SZ_IN_BYTES (8LL)

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, int fd,
            struct msr_batch_array *bstart, struct msr_batch_array *bstop);
void print_elapsed( struct timeval *start, struct timeval *stop, char const * const file, int line, char const * const msg );
void print_byte_string( unsigned char const * const buf, size_t length );
void print_batch( struct msr_batch_array *bstart, struct msr_batch_array *bstop );
void execute_ioctl( int fd, struct msr_batch_array *a );

void
execute_ioctl( int fd, struct msr_batch_array *a ){
    int rc = ioctl( fd, X86_IOC_MSR_BATCH, a );
    if( rc != 0 ){
        fprintf(stdout, "ioctl failed, rc = %d\n", rc);
        exit(-1);
    }

}

void
print_byte_string( unsigned char const * const buf, size_t length ){
    printf("0x");
    for( size_t i=0; i<length; i++ ){
        printf("%02x", buf[i]);
    }
}

void print_elapsed( struct timeval *start, struct timeval *stop, char const * const file, int line, char const * const msg ){
    if( NULL == file ){
        printf("%10.8lf ", (stop->tv_sec - start->tv_sec) + (stop->tv_usec - start->tv_usec)/1000000.0);
    }else{
        printf("%s:%d %10.8lf %s\n",
                file, line,
                (stop->tv_sec - start->tv_sec) + (stop->tv_usec - start->tv_usec)/1000000.0,
                msg);
    }
}

void
print_batch( struct msr_batch_array *bstart, struct msr_batch_array *bstop ){
    uint64_t energy = (bstart->ops[0].msrdata > bstop->ops[0].msrdata)
                        ? (UINT32_MAX - bstart->ops[0].msrdata) + bstop->ops[0].msrdata
                        : bstop->ops[0].msrdata - bstart->ops[0].msrdata;
    uint64_t aperf  = (bstart->ops[1].msrdata > bstop->ops[1].msrdata)
                        ? (UINT64_MAX - bstart->ops[1].msrdata) + bstop->ops[1].msrdata
                        : bstop->ops[1].msrdata - bstart->ops[1].msrdata;
    uint64_t mperf  = (bstart->ops[2].msrdata > bstop->ops[2].msrdata)
                        ? (UINT64_MAX - bstart->ops[2].msrdata) + bstop->ops[2].msrdata
                        : bstop->ops[2].msrdata - bstart->ops[2].msrdata;
    printf("%"PRIu64" %"PRIu64" %"PRIu64" ", energy, aperf, mperf);
}

int
main (void)
{
    struct timeval start, stop;
    struct msr_batch_array batch_start, batch_stop;
    struct msr_batch_op ops_start[3], ops_stop[3];

    // Set up msr-safe batch calls.
    int fd = open("/dev/cpu/msr_batch", O_RDWR);
    assert(-1 != fd);

    batch_start.numops = batch_stop.numops = 3;
    batch_start.ops    = ops_start;
    batch_stop.ops     = ops_stop;

    for( ssize_t i = 0; i < 3; i++ ){
        ops_start[i].cpu     = ops_stop[i].cpu     = 70;
        ops_start[i].isrdmsr = ops_stop[i].isrdmsr =  1;
        ops_start[i].err     = ops_stop[i].err     =  0;
        ops_start[i].msrdata = ops_stop[i].msrdata =  0;
        ops_start[i].wmask   = ops_stop[i].wmask   =  0;
    }
    ops_start[0].msr = ops_stop[0].msr = 0x611;    // Energy is the bottom 32 bits
    ops_start[1].msr = ops_stop[1].msr = 0x0E8;    // APERF 64-bits
    ops_start[2].msr = ops_stop[2].msr = 0x0E7;    // MPERF 64-bits

    // Set up a pile of random keys.
    assert( NUM_KEYS * KEY_SZ_IN_BYTES < INT_MAX );
    gettimeofday( &start, NULL );
    unsigned char *keys = calloc( NUM_KEYS, KEY_SZ_IN_BYTES );
    assert(keys);
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( NUM_KEYS, KEY_SZ_IN_BYTES )" );
    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( keys, NUM_KEYS * KEY_SZ_IN_BYTES ) );
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( keys, NUM_KEYS * KEY_SZ_IN_BYTES )" );

    // Set up a pile of random nonces
    assert( NUM_NONCES * NONCE_SZ_IN_BYTES < INT_MAX );
    gettimeofday( &start, NULL );
    unsigned char *ivs = calloc( NUM_NONCES, NONCE_SZ_IN_BYTES );
    assert(ivs);
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( NUM_NONCES, NONCE_SZ_IN_BYTES )" );
    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( ivs, NUM_NONCES * NONCE_SZ_IN_BYTES ) );
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( ivs, NUM_NONCES * NONCE_SZ_IN_BYTES )" );

    // Set up long, random, plaintext message.
    gettimeofday( &start, NULL );
    unsigned char *plaintext = calloc( PLAINTEXT_BUF_SZ, 1 );
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( PLAINTEXT_BUF_SZ, 1 )" );
    assert( plaintext );
    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( plaintext, PLAINTEXT_BUF_SZ ) );
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( plaintext, PLAINTEXT_BUF_SZ )" );

    // Set up (longer) buffer for encrypted text.
    gettimeofday( &start, NULL );
    unsigned char *ciphertext = calloc( CRYPTTEXT_BUF_SZ, 1 );
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( CRYPTTEXT_BUF_SZ, 1 )" );
    assert( ciphertext );

    // Do the encryption
    int ciphertext_len;
    for( size_t key_idx=0, iv_idx=0; key_idx<NUM_KEYS*KEY_SZ_IN_BYTES; key_idx += KEY_SZ_IN_BYTES, iv_idx += NONCE_SZ_IN_BYTES ){
        sleep(2);  // Allow processor to return to quiescent state
        print_byte_string( &keys[key_idx], KEY_SZ_IN_BYTES );
        printf(" ");
        print_byte_string( &ivs[iv_idx], NONCE_SZ_IN_BYTES );
        printf(" ");
        gettimeofday( &start, NULL );
        ciphertext_len = encrypt (plaintext, PLAINTEXT_BUF_SZ, &keys[key_idx], &ivs[iv_idx], ciphertext, fd, &batch_start, &batch_stop);
        gettimeofday( &stop, NULL );
        print_elapsed( &start, &stop, NULL, 0, NULL);
        print_batch( &batch_start, & batch_stop );
        printf("\n");
    }

    // Report out some details
    printf(" %d bytes of plaintext, %d bytes encrypted buffer, %d bytes encrypted text, %d bytes of unused buffer.\n",
            PLAINTEXT_BUF_SZ,  CRYPTTEXT_BUF_SZ, ciphertext_len, CRYPTTEXT_BUF_SZ - ciphertext_len );

    return 0;
}

void
handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, int fd,
            struct msr_batch_array *bstart, struct msr_batch_array *bstop){

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
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptInit_ex( ... )" );

    // One-shot encryption
    gettimeofday( &start, NULL );
    execute_ioctl( fd, bstart );
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    execute_ioctl( fd, bstop );
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptUpdate( ... )" );
    ciphertext_len = len;

    // Finalize
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    gettimeofday( &stop, NULL );
    //print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptFinal_ex( ... )" );
    ciphertext_len += len;

    // Clean up 
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
