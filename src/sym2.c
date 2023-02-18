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

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
/*
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
*/
void print_elapsed( struct timeval *start, struct timeval *stop, char const * const file, int line, char const * const msg );

void print_elapsed( struct timeval *start, struct timeval *stop, char const * const file, int line, char const * const msg ){
    printf("%s:%d %lf %s\n",
            file, line,
            (stop->tv_sec - start->tv_sec) + (stop->tv_usec - start->tv_usec)/1000000.0,
            msg);
}

int main (void)
{
    struct timeval start, stop;
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    /*
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";
    */
    gettimeofday( &start, NULL );
    unsigned char *plaintext = calloc( PLAINTEXT_BUF_SZ, 1 );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( PLAINTEXT_BUF_SZ, 1 )" );
    assert( plaintext );

    gettimeofday( &start, NULL );
    assert( 1 == RAND_bytes( plaintext, PLAINTEXT_BUF_SZ ) );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "RAND_bytes( plaintext, PLAINTEXT_BUF_SZ )" );



    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    gettimeofday( &start, NULL );
    unsigned char *ciphertext = calloc( CRYPTTEXT_BUF_SZ, 1 );
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "calloc( CRYPTTEXT_BUF_SZ, 1 )" );
    assert( ciphertext );

    /* Buffer for the decrypted text */
    //unsigned char decryptedtext[128];

    //int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    gettimeofday( &start, NULL );
    int ciphertext_len = encrypt (plaintext, PLAINTEXT_BUF_SZ, key, iv,
                              ciphertext);
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "encrypt( ... )" );

    printf(" %d bytes of plaintext, %d bytes encrypted buffer, %d bytes encrypted text, %d bytes of unused buffer.\n",
            PLAINTEXT_BUF_SZ,  CRYPTTEXT_BUF_SZ, ciphertext_len, CRYPTTEXT_BUF_SZ - ciphertext_len );

    /* Do something useful with the ciphertext here */
    //printf("Ciphertext is:\n");
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    //decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
    //                            decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    //decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    //printf("Decrypted text is:\n");
    //printf("%s\n", decryptedtext);


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

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptInit_ex( ... )" );

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptUpdate( ... )" );
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    gettimeofday( &start, NULL );
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    gettimeofday( &stop, NULL );
    print_elapsed( &start, &stop, __FILE__, __LINE__, "EVP_EncryptFinal_ex( ... )" );
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
#if 0
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

#endif //0
