/*!
*****************************************************************
* @file    waterpipe.c
* @brief   RBP WATERPIPE
* @author  Lukasz Piatek
* @version V1.0
* @date    2021-09-28
* @brief   BME280 Driver
* @copyright Copyright (c) Lukasz Piatek. All rights reserved.
*****************************************************************
*/

/*=========================================================*/
/*== INCLUDES =============================================*/
/*=========================================================*/
#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
//#include <ctime>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include "waterpipe.h"
#include "test.c"
/*=========================================================*/
/*== TERMINAL PRINTCLEAR ==================================*/
/*=========================================================*/
#define clrscr() printf("\e[1;1H\e[2J") // Clear screen.

/*=========================================================*/
/*== PWM MACROS ===========================================*/
/*=========================================================*/

#define SWPWM_PIN29 29
#define SWPWM_PIN28 28

#define PWM_PIN0 26
#define PWM_PIN1 23
#define L293D_IN1 0
#define L293D_IN2 2
#define L293D_EN1 3

#define L293D_IN3 1
#define L293D_IN4 4
#define L293D_EN2 5

/*=========================================================*/
/*== GLOBAL VARIABLES =====================================*/
/*=========================================================*/
uint16_t pwmRange = 1000;
int32_t pwmClockDefault = 54e6;
float_t pwmDC = 0.1;
uint8_t swTimerFact = 10;
uint8_t swPwmPeriod = 5; /*!< in ms */
uint8_t runMotA = 0;
uint8_t val[1024];
int socketPi;
int status;
int bytesRead;
char data[1024] = {0};
char bme_TX_buffer[60];
float temperature, pressure, humidity, waterLevel, waterTemperature;
char *endTermimn = "ÿ";
// function for randomization
double rand_range(double min, double max)
{ 
    double random = ((double) rand()) / RAND_MAX;
 double range = (max - min) * random;
 double number = min + range;
  
  return number;
}

void HC05_TX_BME280(uint8_t *buffer)
{
uint8_t RecData[50];
    uint8_t TempData[5];
    float_t temperature;
    temperature = rand_range(-50,50);
    gcvt(temperature,5,TempData);
    
    // needed to test if padding is working
    uint8_t in2[8] = {0xff, 0xfe, 0xfd, 0xfc,0xfb, 0xfa, 0xf9, 0xf8};
    strcpy(RecData,"A:");
    strncat(RecData,TempData,sizeof(TempData));
    strncat(RecData,"ÿ",sizeof("ÿ"));

    /* Pressure float to string */
    temperature = rand_range(-5,5);
    gcvt(temperature,5,TempData);
    strncat(RecData,"B:",sizeof("B:"));
    strncat(RecData,TempData,sizeof(TempData));
    strncat(RecData,"ÿ",sizeof("ÿ")); 

    /* Humidity float to string */
    temperature = rand_range(-5,5);
    gcvt(temperature,5,TempData);
    strncat(RecData,"C:",sizeof("C:"));
    strncat(RecData,TempData,sizeof(TempData));
    strncat(RecData,"ÿ",sizeof("ÿ")); 
    strncat(buffer,RecData,sizeof(RecData));
    printf("Sending string %s",buffer);

}

int main(void)
{
    srand(time(NULL));
    
    printf("\n\n************************************\n");   
    printf("start main\n");
    printf("\n\n************************************\n");

    // needed to test if padding is working
    uint8_t in2[8] = {0xff, 0xfe, 0xfd, 0xfc,0xfb, 0xfa, 0xf9, 0xf8};
  
    encrypt_cbc(in2,8);
    
    decrypt_input_cbc(encryptedPaket,val);

    memset(encryptedPaket,0,sizeof(encryptedPaket));
  // for(int i=0; i<51;i++){
    HC05_TX_BME280( bme_TX_buffer);   
    encrypt_cbc((uint8_t *)bme_TX_buffer,sizeof(bme_TX_buffer));
    memcpy(bme_TX_buffer, encryptedPaket,sizeof(encryptedPaket));
    decrypt_input_cbc(bme_TX_buffer, val);
    memset(bme_TX_buffer, 0, sizeof(bme_TX_buffer));
    memset(encryptedPaket,0,sizeof(encryptedPaket));
    printf("\n\nReceived String :%s\n\n",val);
   
       filterChar(val, "A:", "ÿ","[X] BME TEMP: ","°C"); //"ÿ"
        filterChar(val, "B:",  "ÿ","[X] BME PRESS: ","hPa");
        filterChar(val, "C:",  "ÿ","[X] BME HUM: ","%");
        filterChar(val, "D:",  "ÿ","[X] DS18B20 TEMP: ","°C");
        if(filterChar(val, "E:",  "ÿ","[X] WATERLEVEL: ","cm") >= 4.0f)
        {
            pwmWrite(PWM_PIN1, 0);
        }
        else
        {
            pwmWrite(PWM_PIN1, 1023);
        }
        
        //memset(data, 0, sizeof(data));
        memset(val, 0, sizeof(val));
   // decrypt_input_cbc(encryptedPaket);  
    memset(bme_TX_buffer, 0, sizeof(bme_TX_buffer));
    memset(encryptedPaket,0,sizeof(encryptedPaket));
    //encrypt_cbc(in2,8);
    
    
    //https://stackoverflow.com/questions/25360893/convert-char-to-uint8-t
}


/*!
**************************************************************
* @brief
*
* @param[in]  :
*
* @return Result of API execution status
*
* @retval = 0 -> Success.
* @retval > 0 -> Warning.
* @retval < 0 -> Fail.
*
*
**************************************************************
*/
void debugTerm(void)
{
    debugMsg("\n\n======================================================================\r\n");
    debugMsg("======================== DEBUG TERMINAL===============================\r\n");
    debugMsg("======================================================================\r\n\n");
}


float filterChar(char *string, char *searchString, char *term, char *output,char *unit)
{
    int len;
    char buff[strlen(searchString)];
    char data[strlen(searchString)];
    char *ret = strstr(string, searchString);

    if (ret != 0)
    {

        for (int i = 0; i < strlen(searchString); ++i)
        {
            buff[i] = ret[i];
            //printf("buff[i] %c\n",buff[i] );
            //printf("searchstring: %s\n", searchString);
        }

    }
//strcmp(buff, searchString)
    if (strstr(searchString,buff ) == 0 && ret != 0)
    {

        len = strcspn(ret, term);
        char buff[len];

        for (int i = 0; i < len; ++i)
        {
            buff[i] = ret[i + strlen(searchString)];
            data[i] = ret[i + strlen(searchString)];
        }

        buff[len - strlen(searchString)] = '\0';//'\0'; //"ÿ"; //'\0'
        data[len - strlen(searchString)] = '\0';//'\0';//"ÿ";
       // debug2Val("\r\n %s%s [X] \r\n", searchString, buff);
        debug2Val("\r\n %s%s [X] \r\n", output, strncat(data,unit,sizeof(unit)));

        return strtod(buff, NULL); /*!< strtod gives better control of undefined range */
    }
    else
    {
        //  debugMsg("=============================\r\n");
		// debugVal("%s not found\r\n",searchString);
		// debugMsg("=============================\r\n"); 
        return -200;
    }
    
 }
