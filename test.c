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

uint8_t *encryptBuffer[64];
uint8_t *encryptedPaket[89];
static void phex(uint8_t *str);
uint8_t *decrpytBuffer[64];
uint8_t iv[16]; //128 bitinitialization vector
uint8_t* Decryptiv[16]; //128 bitinitialization vector
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
    printf("\n************************************\n");
    printf("\nORIGINAL DATA (size is %i bytes):\n\n", testDataLength);
    for (uint8_t i = 0; i < testDataLength; i++)
    {
        printf("%x", testData[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("\n\n************************************\n");
    printf("\nblock size(size is %i bytes):\n\n", BLOCK_SIZE);
    PKCS7_Padding *structWithPaddingResult = addPadding(testData, testDataLength, BLOCK_SIZE);
    uint8_t *ptrToPaddingDataResult = structWithPaddingResult->dataWithPadding;
    printf("\nWITH PADDING (now size is %li bytes):\n\n", structWithPaddingResult->dataLengthWithPadding);
    for (uint16_t i = 0; i < structWithPaddingResult->dataLengthWithPadding; i++)
    {
        printf("%x", *ptrToPaddingDataResult);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
        ptrToPaddingDataResult++;
    }
}
//// Function to remove PKSC7 Padding 
void unPaddingCipher(const void *const data, const uint64_t dataLength)
{
    printf("\n************************************\n");
    printf("\nStart unpadding\n");
    PKCS7_unPadding *structWithUnpaddingResult = removePadding(data, dataLength);
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
static int decrypt_input_cbc(uint8_t *in)
{   
    //extractFlags();
    uint8_t startFlag[4];
    uint8_t endflagFlag[5];
    uint8_t cipher[64]; 

    for(int i=0; i<4; i++){
         startFlag[i] = in[i];
    }
     printf("\n************************************\n");
    printf("\nStartFlag:\n\n");
    for (uint8_t i = 0; i < 5; i++)
    {
     printf("%x", startFlag[i]);
     ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("end of endflag \n");
    for(int i=85; i<90; i++){
         endflagFlag[i] = in[i];
    }


      printf("\n************************************\n");
    printf("\n>EndFlag:\n\n");
    for (uint8_t i = 0; i < 6; i++)
    {
     printf("%x", endflagFlag[i]);
     ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

   for (size_t i = 4; i <20; i++)
    {
        Decryptiv[i] = in[i];
    } 
      printf("\n************************************\n");
    printf("\n>IV:\n\n");
    for (uint8_t i = 0; i < 6; i++)
    {
     printf("%x", Decryptiv[i]);
     ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

    for (size_t i = 20; i < 85; i++)
    {
        cipher[i] = in[i];
    }
 



    size_t n = sizeof(in);
    int testNumber = 1;
    if (testNumber == 1)
    {
        printf("remove padding");
    }
    for (size_t i = 0; i < 64; i++)
    {
        decrpytBuffer[i] = encryptBuffer[i];
    }
    printf("decrypt function cbc start\n");
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, decrpytBuffer, 64);

    printf("\nTest with decrptBuffer!\n");
    if (0 == memcmp((char *)out, (char *)decrpytBuffer, 64))
    {
        printf("SUCCESS in decryptBuffer!\n");
        return (0);
    }
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
    shuffle(charset, (int) (sizeof charset), sizeof(char));
    printf("%d\n", rand() % (int) (sizeof charset - 1));
    int key = rand() % (int) (sizeof charset - 1);
    str[n] = charset[key];
  }

  str[size] = '\0';

  return str;
}

void calculateIV(uint8_t* iv){
   int iv_len;
    iv_len = 16;
    random_string(iv, iv_len);
      printf("\n\n************************************\n");
    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%x", iv[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("\n\n************************************\n");
}

static uint8_t encrypt_cbc(uint8_t *in)
{
    int iv_len;
    iv_len = 16;
    random_string(iv, iv_len);
    //calculateIV(iv);
    for (size_t i = 0; i <16; i++)
    {
    printf("%x", iv[i]);
     ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
     }
      printf("\n\n************************************\n");
   
    uint8_t nTest = sizeof(in);
    uint8_t blockSize = 256 / 8;

    printf("\n************************************\n");
    printf("\nORIGINAL DATA (size is %i bytes) before Padding:\n\n", nTest);
    for (uint8_t i = 0; i < nTest; i++)
    {
        printf("%x", in[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("Blocksize is: %d", blockSize);
    printf("\n\n************************************\n");
    if (sizeof(in) < blockSize)
    {
        PaddingPlainText(in, nTest, blockSize);
    }
    //https://github.com/GRISHNOV/PKCS7-Padding/blob/master/src/PKCS7.c

    uint8_t out[] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                     0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                     0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                     0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};
    printf("\n\n************************************\n");
    printf("encrypt function cbc start\n");
    memcpy((char *)encryptBuffer, (char *)in, sizeof(encryptBuffer));
    struct AES_ctx ctx;
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);
    
    printf("CBC encrypt: ");
   
    
    encryptedPaket[0] = 0x79; //Start flag 
    encryptedPaket[1] = 0x3a; //
    encryptedPaket[2] = 0x2f; //
    encryptedPaket[3] = 0x3d; // Assci y:
    encryptedPaket[85] = 0x32; // End Flag
    encryptedPaket[86] = 0x35; //
    encryptedPaket[87] = 0x35; //
    encryptedPaket[88] = 0x2f; //
    encryptedPaket[89] = 0x3d; //

    printf("\n\n************************************\n");
    printf("IV\n");
    
    for (size_t i = 4; i <20; i++)
    {
        encryptedPaket[i] = iv[i];
    }
    for (size_t i = 20; i < 85; i++)
    {
        encryptedPaket[i] = in[i];
    }
    
    printf("\n\n************************************\n");
    printf("Final message\n");
    for (uint8_t i = 0; i < 90; i++)
    {
     printf("%x", encryptedPaket[i]);
     ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("end of encrypt function\n");
    printf("\n\n************************************\n");
     if (0 == memcmp((char *)out, (char *)in, 64))
    {
        printf("SUCCESS!\n");
        return (0);
    }
    else
    {
        printf("FAILURE!\n");
        return (1);
    }
}


