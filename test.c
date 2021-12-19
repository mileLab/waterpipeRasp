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

uint8_t *encryptBuffer[32];
uint8_t encryptedPaket2[48];
uint8_t encryptedPaket[57];
static void phex(uint8_t *str);
uint8_t *decrpytBuffer[16];
uint8_t *ptrToPaddingDataResultBuffer[32];
PKCS7_Padding *structWithPaddingResult;
PKCS7_unPadding *structWithUnpaddingResult;

uint8_t* iv[16];         //128 bitinitialization vector
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
    
    printf("\n\n************************************\n");
    printf("\nblock size(size is %i bytes):\n\n", BLOCK_SIZE);
    structWithPaddingResult = addPadding(testData, testDataLength, BLOCK_SIZE); 
    uint8_t *ptrToPaddingDataResult = structWithPaddingResult->dataWithPadding;
    printf("\n Add PADDING (size is %li bytes):\n\n", structWithPaddingResult->dataLengthWithPadding);
    
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
    structWithUnpaddingResult = removePadding(data, dataLength);
   /* uint8_t *ptrToUnpaddingDataResult = structWithUnpaddingResult->dataWithoutPadding;

    printf("\nREMOVE PADDING (size is %li bytes):\n\n", structWithUnpaddingResult->dataLengthWithoutPadding);
    for (uint16_t i = 0; i < structWithUnpaddingResult->dataLengthWithoutPadding; i++)
    {
        printf("%x", *ptrToUnpaddingDataResult);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
        ptrToUnpaddingDataResult++;
    } */
    printf("\n\n************************************\n\n");
}
static int decrypt_input_cbc(uint8_t *in)
{
    uint8_t* Decryptiv[16]; 
    for (uint8_t i = 0; i < 58; i++)
    {
        printf("%x", in[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

    //extractFlags();
    uint8_t startFlag[4];
    uint8_t endflagFlag[5];
    uint8_t cipher[32];

    for (int i = 0; i < 4; i++)
    {
        startFlag[i] = in[i];
    }
    printf("\n************************************\n");
    printf("\nStartFlag:\n\n");
    for (uint8_t i = 0; i < 5; i++)
    {
        printf("%x", startFlag[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    
    for (int i = 53; i < 58; i++)
    {
        endflagFlag[i - 85] = in[i];
    }

    printf("\n************************************\n");
    printf("\n>EndFlag:\n\n");
    for (uint8_t i = 0; i < 6; i++)
    {
        printf("%x", endflagFlag[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    
    for (size_t i = 4; i < 20; i++)
    {
        Decryptiv[i - 4] = in[i-4];
    }
     if (0 == memcmp(iv,Decryptiv, 16))
    {
        printf("IV the same!\n");
    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%x", Decryptiv[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
        return (0);
    }else{
         printf("\nIV not the same!\n");
     
    }
    }

    printf("\n************************************\n");
    printf("\n>IV:\n\n");
    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%x", Decryptiv[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

    for (size_t i = 20; i < 53; i++)
    {
        cipher[i - 20] = in[i];
    }
    printf("\n************************************\n");
    printf("\n>Cipher:\n\n");
    for (uint8_t i = 0; i < 32; i++)
    {
        printf("%x", cipher[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    size_t n = sizeof(in);
    int testNumber = 1;
    uint8_t cipherLength = sizeof(cipher);
    printf("\nCipgher lenght\n");
    printf("%d", cipherLength);
  
    printf("decrypt function cbc start\n");
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
     uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t out2[] = {0xff, 0xfe, 0xfd, 0xfc,0xfb, 0xfa, 0xf9, 0xf8};
    //uint8_t iv2[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,    };

    struct AES_ctx ctx;
    printf("\n************************************\n");
      for (uint8_t i = 0; i < 32; i++)
    {
        printf("%x", encryptedPaket2[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("\n************************************\n");

    AES_init_ctx_iv(&ctx, key, Decryptiv);
    AES_CBC_decrypt_buffer(&ctx, encryptedPaket2, 32);
    if (testNumber == 1)
    {   printf("\n************************************\n");
         for (uint8_t i = 0; i < 32; i++)
    {
        printf("%x", encryptedPaket2[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

        //removePadding(cipher,cipherLength);
        printf("remove padding");
    }
    memcmp(iv, (char *)decrpytBuffer, 16); //copy Iv
    printf("\nTest with decrptBuffer!\n");
    if (0 == memcmp((char *)out2, (char *)decrpytBuffer, 32))
    {
        printf("SUCCESS in decryptBuffer!\n");
    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%x", decrpytBuffer[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
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
        shuffle(charset, (int)(sizeof charset), sizeof(char));
        printf("%d\n", rand() % (int)(sizeof charset - 1));
        int key = rand() % (int)(sizeof charset - 1);
        str[n] = charset[key];
    }

    str[size] = '\0';

    return str;
}

void calculateIV(uint8_t *iv)
{
    int iv_len;
    iv_len = 16;
    random_string(iv, iv_len);
    printf("\n\n************************************\n");
    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%x", iv[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    return 0;
    printf("\n\n************************************\n");
}

static uint8_t encrypt_cbc(uint8_t *in)
{
  /* int iv_len;
    iv_len = 16;
    random_string(iv, iv_len); */
    calculateIV(iv);
    uint8_t nTest = sizeof(in);
    uint8_t blockSize = 256 / 8;
    

   /*Ä printf("\n************************************\n");
    printf("\nORIGINAL DATA (size is %i bytes) before Padding:\n\n", nTest);
    for (uint8_t i = 0; i < nTest; i++)
    {
        printf("%x", in[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }

     printf("\n\n************************************\n");
    printf("Startpadding Blocksize  is: %d", blockSize);
   */
    if (sizeof(in) < blockSize)
    {
       PaddingPlainText(in, nTest, blockSize);
    }
     printf("\n\n************************************\n");
    //https://github.com/GRISHNOV/PKCS7-Padding/blob/master/src/PKCS7.c

    uint8_t out[] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                     0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                     0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                     0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};
    printf("\n\n************************************\n");
    printf("START ENCRYPTION\n");
    printf("\n\n************************************\n");
    uint8_t *ptrToPaddingDataResult2 = structWithPaddingResult->dataWithPadding;
   
    struct AES_ctx ctx;
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
     
    for (uint8_t i = 0; i < 32; i++)
    {
        printf("%x", ptrToPaddingDataResult2[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    } 
    //uint8_t iv2[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,};
                      
                      
     printf("\n\n************************************\n");
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, ptrToPaddingDataResult2, 32);
    for (uint8_t i = 0; i < 32; i++)
    {
        printf("%x", ptrToPaddingDataResult2[i]);
        
    }
    


    encryptedPaket[0] = 0x79;  //Start flag
    encryptedPaket[1] = 0x3a;  //
    encryptedPaket[2] = 0x2f;  //
    encryptedPaket[3] = 0x3d;  // Assci y:
    encryptedPaket[53] = 0x32; // End Flag
    encryptedPaket[54] = 0x35; //
    encryptedPaket[55] = 0x35; //
    encryptedPaket[56] = 0x2f; //
    encryptedPaket[57] = 0x3d; //

    for (size_t i = 4; i < 20; i++)
    {
        encryptedPaket[i] = iv[i - 4];
        encryptedPaket2[i-4] = iv[i - 4];
    }
    for (size_t i = 20; i < 58; i++)
    {
        encryptedPaket[i] = ptrToPaddingDataResult2[i - 20];
        encryptedPaket2[i-4] = ptrToPaddingDataResult2[i - 20];
    }
    
    printf("\n\n************************************\n");
    printf("Final encryptedPaket2 which will be send:\n");
    for (uint8_t i = 0; i < 32; i++)
    {
        printf("%x", encryptedPaket2[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("\n\n************************************\n");
   
    printf("\n\n************************************\n");
    printf("Final Paket which will be send:\n");
    for (uint8_t i = 0; i < 58; i++)
    {
        printf("%x", encryptedPaket[i]);
        ((i + 1) % 4 == 0) ? printf("\n") : printf("\t");
    }
    printf("\n\n************************************\n");
    printf("end of encrypt function\n");
    printf("\n\n************************************\n");
    if (0 == memcmp((char *)out, (char *)in, 32))
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
