#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "PKSC7.h"
//https://thmsdnnr.com/blog/lets-implement-pkcs7-padding/
PKCS7_Padding* addPadding(const void* const data, const uint64_t dataLength, const uint8_t BLOCK_SIZE)
{
    if (0 == BLOCK_SIZE)
    {
        puts("ERROR: block is not valid");
        exit(-1);
    }
    
    PKCS7_Padding* paddingResult = (PKCS7_Padding*) malloc(sizeof(PKCS7_Padding));
    if (NULL == paddingResult)
    {
        perror("problem with PKCS7_Padding* paddingResult");    /* if memory allocation failed */
        exit(-1);
    }

    uint8_t paddingBytesAmount = BLOCK_SIZE - (dataLength % BLOCK_SIZE);  /* number of bytes to be appended */
 //   printf("padding ammount needed %d",paddingBytesAmount); //print needed padding amount 
    paddingResult->valueOfByteForPadding = paddingBytesAmount;      
  //   printf("paddingResult->valueOfByteForPadding %d",paddingResult->valueOfByteForPadding);                /* according to the PKCS7 */
 //   printf("dataLength %d",dataLength);
    paddingResult->dataLengthWithPadding = dataLength + paddingBytesAmount;         /* size of the final result */
  //  printf("Data length with padding %li",paddingResult->dataLengthWithPadding); 
    uint8_t* dataWithPadding = (uint8_t*) malloc(paddingResult->dataLengthWithPadding);
    if (NULL == paddingResult)
    {
        perror("problem with uint8_t* dataWithPadding");  /* if memory allocation failed */
        exit(-1);
    }
    
    memcpy(dataWithPadding, data, dataLength);  /* copying the original data for further adding padding */
    for (uint8_t i = 0; i < paddingBytesAmount; i++)
    {
        dataWithPadding[dataLength + i] = paddingResult->valueOfByteForPadding;   /* adding padding bytes */
    }
    paddingResult->dataWithPadding = dataWithPadding;
    // printf("\nWITH PADDING (now size is %li bytes):\n\n", paddingResult->dataLengthWithPadding); 
    return paddingResult;
}

PKCS7_unPadding* removePadding(const void* const data, const uint8_t dataLength)
{
    PKCS7_unPadding* unpaddingResult = (PKCS7_unPadding*) malloc(sizeof(PKCS7_unPadding));
    if (NULL == unpaddingResult)
    {
        perror("problem with PKCS7_Padding* unpaddingResult");  /* if memory allocation failed */
        exit(-1);
    }
    
    uint8_t paddingBytesAmount                  = *((uint8_t *)data + dataLength - 1);  /* last byte contains length of data to be deleted */
    unpaddingResult->valueOfRemovedByteFromData = paddingBytesAmount;                   /* according to the PKCS7 */
    unpaddingResult->dataLengthWithoutPadding   = dataLength - paddingBytesAmount;      /* size of the final result */

    uint8_t* dataWithoutPadding = (uint8_t*) malloc(unpaddingResult->dataLengthWithoutPadding);
    if (NULL == dataWithoutPadding)
    {
        perror("problem with uint8_t* dataWithoutPadding");   /* if memory allocation failed */
        exit(-1);
    }

    memcpy(dataWithoutPadding, data, unpaddingResult->dataLengthWithoutPadding);    /* taking data without bytes containing the padding value */
    unpaddingResult->dataWithoutPadding = dataWithoutPadding;

    return unpaddingResult;

    }