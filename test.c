#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1
//#include "randomization.h"
#include "aes.h"
#include "PKSC7.h"

uint8_t startFlag[4];
uint8_t endFlag[5];
uint8_t *encryptBuffer[32];
uint8_t encryptedPaket2[48];
uint8_t encryptedPaket[57];
char srcbuffer[100];
static void phex(uint8_t *str);
uint8_t *decrpytBuffer[16];
uint8_t *ptrToPaddingDataResultBuffer[32];
PKCS7_Padding *structWithPaddingResult;
PKCS7_unPadding *structWithUnpaddingResult;

uint8_t iv[16]; //128 bitinitialization vector

//128 bitinitialization vector
static int test_encrypt_cbc(void);
static int test_decrypt_cbc(void);

static int test_encrypt_ecb(void);
static int test_decrypt_ecb(void);
static void test_encrypt_ecb_verbose(void);

// prints string as hex
static void phex(uint8_t *str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}
// Function to add PKSC7 Padding to CBC
void PaddingPlainText(const uint8_t *const plainTextData, const uint16_t dataBitLength, const uint8_t BLOCK_SIZE)
{
    uint8_t testDataLength = dataBitLength;
    uint8_t *testData = (uint8_t *)malloc(testDataLength);
    memcpy(testData, plainTextData, testDataLength);

    /*printf("\n\n************************************\n");
    printf("\nblock size(size is %i bytes):\n\n", BLOCK_SIZE); */
    structWithPaddingResult = addPadding(testData, testDataLength, BLOCK_SIZE);
    uint8_t *ptrToPaddingDataResult = structWithPaddingResult->dataWithPadding;
    /*  printf("\n Add PADDING (size is %li bytes):\n\n", structWithPaddingResult->dataLengthWithPadding);
    
    for (uint16_t i = 0; i < structWithPaddingResult->dataLengthWithPadding; i++)
    {
        printf("%x", *ptrToPaddingDataResult);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
        ptrToPaddingDataResult++;
    }  
    */
}
//// Function to remove PKSC7 Padding
void unPaddingCipher(const void *const data, const uint8_t dataLength)
{
    printf("\n************************************\n");
    printf("\nStart unpadding\n");
    printf("%d", dataLength);
    structWithUnpaddingResult = removePadding(data, dataLength);
    uint8_t *ptrToUnpaddingDataResult = structWithUnpaddingResult->dataWithoutPadding;

    printf("\nREMOVE PADDING (size is %li bytes):\n\n", structWithUnpaddingResult->dataLengthWithoutPadding);
    for (uint16_t i = 0; i < structWithUnpaddingResult->dataLengthWithoutPadding; i++)
    {
        printf("%x", *ptrToUnpaddingDataResult);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
        ptrToUnpaddingDataResult++;
    }
    printf("\n\n************************************\n\n");
}

// function for randomization
int rand_comparison(const void *a, const void *b)
{
    (void)a;
    (void)b;

    return rand() % 2 ? +1 : -1;
    ;
}
// added seed for randomizaiton (no secure random function)
void shuffle(void *base, size_t nmemb, size_t size)
{
    qsort(base, nmemb, size, rand_comparison);
}

// final randomfunction
static char *random_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    int i, n;
    n = 0;

    for (i = 0; n < size; n++)
    {
        shuffle(charset, (int)(sizeof charset), sizeof(char));
        int key = rand() % (int)(sizeof charset - 1);
        str[n] = charset[key];
    }

    str[size] = '\0';

    return str;
}

void calculateIV(uint8_t *iv)
{
    int iv_len = 16;
    random_string(iv, iv_len);
  
}

static uint8_t encrypt_cbc(uint8_t *in, uint8_t inputSize)
{

    calculateIV(iv); // calculate IV everytime new for each run
    for (size_t i = 0; i < 16; i++)
    {
        printf("%x", iv[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

    printf("IV\n");
    uint8_t blockSize = 256 / 8;

    if (sizeof(in) < blockSize)
    {
        PaddingPlainText(in, inputSize, blockSize);
    }
    if (sizeof(in) > blockSize)
    {
        printf("blocksize > 32\r\n");
        return -1;
    }

    printf("\n\n************************************\n");
    //https://github.com/GRISHNOV/PKCS7-Padding/blob/master/src/PKCS7.c

    printf("\n\n************************************\n");
    printf("START ENCRYPTION\n");
    printf("\n\n************************************\n");
    uint8_t *ptrToPaddingDataResult2 = structWithPaddingResult->dataWithPadding;

    struct AES_ctx ctx;
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

   
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, ptrToPaddingDataResult2, 32);
   

    // Defining start and end Flags
    encryptedPaket[0] = 0x79;  //Begin: Start flag
    encryptedPaket[1] = 0x3a;  // Assci y:
    encryptedPaket[2] = 0x2f;  //
    encryptedPaket[3] = 0x3d;  // End: Start Flag
    encryptedPaket[53] = 0x32; // Begine :End Flag
    encryptedPaket[54] = 0x35; //
    encryptedPaket[55] = 0x35; //
    encryptedPaket[56] = 0x2f; //
    encryptedPaket[57] = 0x3d; // End: End flag

    for (size_t i = 4; i < 20; i++)
    {
        encryptedPaket[i] = iv[i - 4];
        encryptedPaket2[i - 4] = iv[i - 4];
    }
    for (size_t i = 20; i < 53; i++)
    {
        encryptedPaket[i] = ptrToPaddingDataResult2[i - 20];
        encryptedPaket2[i - 4] = ptrToPaddingDataResult2[i - 20];
    }
    for (size_t i = 0; i < 32; i++)
    {
        printf("%x", ptrToPaddingDataResult2[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

    printf("end ENCRYPTION\n");
}




static int decrypt_input_cbc(uint8_t *in, char *buff)
{
   
    // Define buffers for Paket
    //uint8_t startFlag[4];
    //uint8_t endFlag[5];
    uint8_t cipher[32];
    uint8_t Decryptiv[16]; 
    //Get Start Flag out of Paket
     for (int i = 0; i < 4; i++)
    {
        startFlag[i] = in[i];
    }
    //Get End Flag out of Paket
    for (int i = 53; i < 58; i++)
    {
        endFlag[i - 58] = in[i];
    }
    //Get IV out of Paket
    for (size_t i = 4; i < 20; i++)
    {
        Decryptiv[i - 4] = in[i];
    }
    /*
     if (0 == memcmp((char *)iv,(char *)Decryptiv, 16))
    {
        printf("Decryption IV the same!\n");
    }else{
         printf("\nIDecrypton V not the same!\n");
    }
    */
    
    // get Cipher text out of Paket (input)
    for (size_t i = 20; i < 53; i++)
    {
        cipher[i - 20] = in[i];
    }
    for (size_t i = 0; i < 32; i++)
    {
         printf("%x", cipher[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    for (size_t i = 0; i < 16; i++)
    {
         printf("%x", Decryptiv[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    
    
    uint8_t cipherLength = sizeof(cipher)*8;
  
    printf("decrypt function cbc start\n");
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t out2[] = {0xff, 0xfe, 0xfd, 0xfc,0xfb, 0xfa, 0xf9, 0xf8};
    
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, Decryptiv);
    AES_CBC_decrypt_buffer(&ctx, cipher, 32);

    printf("\n************************************\n");
    for (size_t i = 0; i < 32; i++)
    {
         printf("%x", cipher[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("\nRemove Padding\n");
    unPaddingCipher(cipher,cipherLength);
    printf("Decrpytion remove padding");
    uint8_t *ptrToPaddingDataResult3 = structWithUnpaddingResult->dataWithoutPadding;
    
    printf("\nDecrpytion Test with decrptBuffer!\n");
    if (0 == memcmp((char *)out2, (char *)ptrToPaddingDataResult3, 8))
    {
        /*
        printf("Decrpytion SUCCESS in decryptBuffer!\n");
    for (uint8_t i = 0; i < 8; i++)
    {
        printf("%x", ptrToPaddingDataResult3[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
        
        */
    }return (0);
   
}
