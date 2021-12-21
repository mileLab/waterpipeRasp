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

int socketPi;
int status;
int bytesRead;
char data[1024] = {0};

float temperature, pressure, humidity, waterLevel, waterTemperature;
char *endTermimn = "ÿ";
// function for randomization

int main(void)
{
    srand(time(NULL));
    
    printf("\n\n************************************\n");   
    printf("start main\n");
    printf("\n\n************************************\n");

    // needed to test if padding is working
    uint8_t in2[8] = {0xff, 0xfe, 0xfd, 0xfc,0xfb, 0xfa, 0xf9, 0xf8};
  
    encrypt_cbc(in2,8);
    
    decrypt_input_cbc(encryptedPaket);

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