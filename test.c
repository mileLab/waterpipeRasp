#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"
#include "PKSC7.h"

uint8_t* encryptBuffer[64];

static void phex(uint8_t* str);
uint8_t decrpytBuffer[64];
//static uint8_t encrypt_cbc(uint8_t *in);
static int test_encrypt_cbc(void);
static int test_decrypt_cbc(void);

static int test_encrypt_ecb(void);
static int test_decrypt_ecb(void);
static void test_encrypt_ecb_verbose(void);

// prints string as hex
static void phex(uint8_t* str)
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


// Padding of blocks if to small 
void PaddingPlainText(const uint8_t* const plainTextData, const uint16_t dataBitLength, const uint8_t BLOCK_SIZE)
{
    uint8_t  testDataLength = dataBitLength / 8;
    uint8_t* testData       = (uint8_t*) malloc(testDataLength);
    printf("\n************************************\n");
    printf("\nORIGINAL DATA (size is %i bytes):\n\n", testDataLength);
    PKCS7_Padding* structWithPaddingResult = addPadding(testData, testDataLength, BLOCK_SIZE); 
    uint8_t* ptrToPaddingDataResult  = structWithPaddingResult->dataWithPadding;  
}
//removal of padding
void unPaddingCipher(const void* const data, const uint64_t dataLength){
     PKCS7_unPadding* structWithUnpaddingResult = removePadding(data, dataLength);
     uint8_t* ptrToUnpaddingDataResult  = structWithUnpaddingResult->dataWithoutPadding;

    printf("\nREMOVE PADDING (size is %li bytes):\n\n", structWithUnpaddingResult->dataLengthWithoutPadding);

}


static int decrypt_input_cbc(uint8_t *in, uint8_t *iv){
    //uint8_t inputBuffer[64];
    //memcpy(inputBuffer, in, sizeof(inputBuffer));
    
      for (size_t i = 0; i < 64; i++){
            decrpytBuffer[i]=encryptBuffer[i];
           //printf("0x%x",in[i]);
        }  
    printf("decrypt function cbc start\n");
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;
    
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, decrpytBuffer, 64);
   
    printf("\nTest with decrptBuffer!\n");
    if (0 == memcmp((char*) out, (char*) decrpytBuffer, 64)) {
        printf("SUCCESS in decryptBuffer!\n");
        return(0);
    } 
}
 
static uint8_t encrypt_cbc(uint8_t *in, uint8_t *iv)
{     
     size_t blockSize = 64;
     // Padding check still in work
     int n = sizeof(in)/sizeof(uint8_t);
    printf("%d",n);
     if (sizeof(in) < blockSize)
        {
        printf("Padding needed");
        } 

      uint8_t out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
   
    printf("encrypt function cbc start\n");

    memcpy((char*) encryptBuffer, (char*) in, sizeof(encryptBuffer));
    struct AES_ctx ctx;
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);

    for (size_t i = 0; i < 64; i++){
            encryptBuffer[i]=in[i];
    }
    //testing encryption still works
    printf("CBC encrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 64)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }

    printf("end of encrypt function\n");
}

