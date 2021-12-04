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


int main(void)
{
    printf("test");
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    printf("before buffer init");
    uint8_t *inputBuffer[64];
    for(int i=0;i<65;i++)  inputBuffer[i] = 1;
    printf("before memecopy");
   // printf("%s",sizeof((char *) in));
   //printf("%s",a);
   memcpy((char*) inputBuffer, (char*) in, sizeof(inputBuffer));
    struct AES_ctx ctx;
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);
    printf("before for");
    /* for (size_t i = 0; i < 127; i++)
        {
            printf("inside For");
            inputBuffer[i]=in[i];
            //printf("%s",inputBuffer[i]);

        }       
        printf("after for");
   // return *inputBuffer; 
*/

 
   // encrypt_cbc(*in); 
}
void useless (void){
    struct sockaddr_rc raspPicoServer = {0};
    const char *raspPico = "98:D3:71:FD:F4:3A";

    raspPicoServer.rc_family = AF_BLUETOOTH;
    raspPicoServer.rc_channel = (uint8_t)1;
    str2ba(raspPico, &raspPicoServer.rc_bdaddr);

    debugMsg("====================  RFCOM SERVER MODE STARTED  ===================== \r\n");
 
    /*!< Allocate socket */
    socketPi = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    raspPicoServer.rc_family = AF_BLUETOOTH;
    raspPicoServer.rc_channel = (uint8_t)1;
    str2ba(raspPico, &raspPicoServer.rc_bdaddr);

    status = connect(socketPi, (struct sockaddr *)&raspPicoServer, sizeof(raspPicoServer));

    if (status < 0)
    {
        perror("get no msg");
    }
    else
    {
    /* 
        bytesRead = read(socketPi, data, sizeof(data));
        if (bytesRead > 0)
        {
            debugVal("%s\n", data);
            memset(data, 0, sizeof(data));
        } 
    */
  
    }

    debugTerm();
    delay(1000);
    debugMsg("====================  wiringPi INIT STARTED  ========================= \r\n");
    delay(1000);
    if (wiringPiSetup() < 0)
    {
        debugMsg("[X] wiringPi Setup failed !!! [X]\r\n");
        return -1;
    }
    else
    {
        debugMsg("[X] wiringPi Setup successfull !!! [X]\r\n");
    }
    delay(1000);
    debugMsg("====================  HW PWM INIT STARTED  =========================== \r\n");
    delay(1000);
    uint8_t freqHz = 50;
    float_t pwmClock = pwmClockDefault / freqHz / pwmRange;
    float_t pwmFreq = pwmClockDefault / pwmClock / pwmRange;
    int dutyCycle = 1023 * pwmDC;

    debugVal("[X] HW PWM CLOCK : %d [X]\r\n", (int32_t)pwmClock);
    debugVal("[X] HW PWM FREQ : %f [X]\r\n", pwmFreq);
    debugVal("[X] HW PWM DutyCycle : %d [X]\r\n", (int32_t)dutyCycle);

    pinMode(PWM_PIN0, PWM_OUTPUT); //pwm output mode
    pinMode(PWM_PIN1, PWM_OUTPUT); //pwm output mode
    debugVal("[X] HW PWM_PIN0 on : GPIO %d in OUTPUT MODE [X]\r\n", PWM_PIN0);
    debugVal("[X] HW PWM_PIN1 on : GPIO %d in OUTPUT MODE [X]\r\n", PWM_PIN1);
    delay(1000);

    debugMsg("====================  SW PWM INIT STARTED  =========================== \r\n");
    pinMode(SWPWM_PIN28, OUTPUT);
    pinMode(SWPWM_PIN29, OUTPUT);
    debugVal("[X] SW PWM_PIN28 on : GPIO %d in OUTPUT MODE [X]\r\n", SWPWM_PIN28);
    debugVal("[X] SW PWM_PIN29 on : GPIO %d in OUTPUT MODE [X]\r\n", SWPWM_PIN29);
    delay(1000);

    debugMsg("====================  HW PWM SETUP STARTED  ========================== \r\n");
    pwmSetMode(PWM_MODE_MS);
    pwmSetClock((int)pwmClock);
    pwmSetRange(pwmRange);

    debugVal("[X] HW PWM MODE SETS TO %s [X]\r\n", "PWM_MODE_MS");
    debugVal("[X] HW PWM PERIOD SETS TO %f ms [X]\r\n", (1 / pwmFreq) * 1000);
    debugVal("[X] HW PWM T_ON SETS TO %f ms [X]\r\n", pwmDC * ((1 / pwmFreq) * 1000));
    debugVal("[X] HW PWM T_OFF SETS TO %f ms [X]\r\n", (1 / pwmFreq) * 1000 - pwmDC * ((1 / pwmFreq) * 1000));

    delay(1000);

    debugMsg("====================  SWW PWM SETUP STARTED  ========================== \r\n");
    softPwmCreate(SWPWM_PIN28, 0, swPwmPeriod * swTimerFact); /*!< range = value(ms)*10 ! Measured with osci !  */
    //softPwmWrite(SWPWM_PIN28,swPwmPeriod * swTimerFact * pwmDC);/*!< DC in percent */
    debugVal("[X] SW PWM PERIOD SETS TO %d ms [X]\r\n", swPwmPeriod);
    debugVal("[X] SW PWM T_ON SETS TO %f ms [X]\r\n", pwmDC * swPwmPeriod);
    debugVal("[X] SW PWM T_OFF SETS TO %f ms [X]\r\n", swPwmPeriod - (pwmDC * swPwmPeriod));

    MOTOR_PINS();
    debugMsg("====================  OPERATION MODE STARTED  ======================== \r\n");
    //delay(5000);


    debugMsg("====================  INIT SIGNAL HANDLER STARTED  =================== \r\n");
    signal(SIGALRM, sig_handler);
    signal(SIGINT, sig_handler);
    //signal(SIGVTALRM, sig_handler);
    alarm(1);
  



    runMotA = 1;
    memset(data, 0, sizeof(data));

    timer_Us(100000);


    while (1)
    {
        //pwmWrite(PWM_PIN0, dutyCycle);/*!< Needs to be in the while loop */
        MOTOR_A_ON(pwmDC);
        //MOTOR_B_ON(511);


    }
    return 0;
}
/*!
**************************************************************
 * @brief Attempt to read the chip-id number of BM*-280 device
 * 
 * @note asdasdas
 * 
 * @warning
 * 
 * @param[in]  deviceAddr Description
 * @param[out]
 *
 * @return Result of reading the ID-register for chip 
 * identification
 *
 * @retval = 0 -> Success
 * @retval > 0 -> Warning
 * @retval < 0 -> Fail
 *
**************************************************************
 */
void MOTOR_PINS(void)
{
    debugMsg("====================  L293D GPIO INIT STARTED  ======================= \r\n");
    pinMode(0, OUTPUT);
    pinMode(2, OUTPUT);
    pinMode(3, OUTPUT);
    pinMode(4, OUTPUT);
    digitalWrite(L293D_EN2, LOW);
    digitalWrite(L293D_IN4, LOW);
}
/*!
**************************************************************
 * @brief Attempt to read the chip-id number of BM*-280 device
 * 
 * @note asdasdas
 * 
 * @warning
 * 
 * @param[in]  deviceAddr Description
 * @param[out]
 *
 * @return Result of reading the ID-register for chip 
 * identification
 *
 * @retval = 0 -> Success
 * @retval > 0 -> Warning
 * @retval < 0 -> Fail
 *
**************************************************************
 */
void MOTOR_A_ON(float_t pwmDC)
{
    //debugMsg("====================  L293D MOTOR-A ROTATING  ======================== \r\n");;
    softPwmWrite(SWPWM_PIN28, swPwmPeriod * swTimerFact * pwmDC); /*!< DC in percent */
    if (runMotA == 1)
    {
        digitalWrite(L293D_EN1, HIGH);
        digitalWrite(L293D_IN2, LOW);
    }
    else
    {
        digitalWrite(L293D_EN1, LOW);
        digitalWrite(L293D_IN2, LOW);
    }

    //debugVal("[X] Motor A Freq with DC: %d\r\n", pwmDC*100);
}
/*!
**************************************************************
 * @brief Attempt to read the chip-id number of BM*-280 device
 * 
 * @note asdasdas
 * 
 * @warning
 * 
 * @param[in]  deviceAddr Description
 * @param[out]
 *
 * @return Result of reading the ID-register for chip 
 * identification
 *
 * @retval = 0 -> Success
 * @retval > 0 -> Warning
 * @retval < 0 -> Fail
 *
**************************************************************
 */
void MOTOR_B_ON(int dutyCycle)
{
    debugMsg("====================  L293D MOTOR-B ROTATING  ======================== \r\n");
    digitalWrite(L293D_EN2, HIGH);
    pwmWrite(PWM_PIN1, dutyCycle);
    digitalWrite(L293D_IN4, LOW);
    debugVal("[X] Motor B Freq with DC: %d\r\n", dutyCycle);
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







void sig_handler(int32_t sigNr)
{

    
    if (sigNr == SIGALRM)
    { //signal handler for SIGALRM


      /*   
      bytesRead = read(socketPi, data, sizeof(data));
        if (bytesRead >= 51)
        {
            debugVal("%s\r\n", data);
            debugVal("Bytes recieved:%d",bytesRead);
            filterChar(data, "TE:","ÿ");
            filterChar(data, "PR:","ÿ");
            filterChar(data, "HM:","ÿ");
            filterChar(data, "TW:","ÿ");
            filterChar(data, "WL:","ÿ");
            memset(data, 0, sizeof(data));       
        }
        else if (bytesRead <= 10)
        {
            bytesRead = read(socketPi, data, sizeof(data));
            debugVal("%s\r\n", data);
            debugVal("Error:Bytes recieved:%d",bytesRead); 
            memset(data, 0, sizeof(data)); 
        } */


        

        memset(data, 0, sizeof(data));
  

        //printf("2 Seconds Signal-IRQ\r\n");
        if (pwmDC < 1)
        {
            pwmDC += 0.1;
            debugVal("[X] POWER %f [X]\r\n",pwmDC);
        }
        else if (pwmDC = 1.0f)
        {
            debugMsg("[X] FULL POWER [X]\r\n");
        }

        else
        {

            __NOP();
        }
        alarm(1);
    }
    else
    {
        __NOP();
    }
    

    if (sigNr == SIGINT)
    { // signal handler for SIGINT
        debugMsg("\n[X] Exit Programm [X]\n");
        runMotA = 0;
        digitalWrite(L293D_EN1, LOW);
        exit(0);
    }
    else
    {
        __NOP();
    }
    
    clrscr();
}

void timer_Us(int64_t uSeconds)
{
    struct sigaction sa;
    struct itimerval timer;

    memset(&sa, 0, sizeof (sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = &timer_handler;
    sigaction(SIGVTALRM, &sa, NULL);

    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = uSeconds;

    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = uSeconds;

    setitimer(ITIMER_VIRTUAL, &timer, NULL);
}

void timer_handler (int32_t sigNr)
{

    bytesRead = read(socketPi, data, sizeof(data));

        debugVal("%s\r\n", data);
        debugVal("Bytes recieved:%d",bytesRead);
        if (bytesRead != -1)
        { 
            filterChar(data, "A:","ÿ");
            filterChar(data, "B:","ÿ");
            filterChar(data, "C:","ÿ");
            filterChar(data, "D:","ÿ");
            filterChar(data, "E:","ÿ"); 
            memset(data, 0, sizeof(data));   
        }
    
    

  }



float filterChar(char *string, char *searchString, char *term)
{
	int len;
	char buff[strlen(searchString)];
	char *ret = strstr(string, searchString);

	if (ret != 0)
	{
		for (int i = 0; i < strlen(searchString); ++i)
		{
			buff[i] = ret[i];
		}
	}

	if (strcmp(buff, searchString) == 0 && ret != 0)
	{

		len = strcspn(ret, term);
		char buff[len];

		for (int i = 0; i < len; ++i)
		{
			buff[i] = ret[i + strlen(searchString)];
		}

		buff[len - strlen(searchString)] ='\0'/*"ÿ"*/;
		debug2Val("\r\n %s%s [X] \r\n",searchString,buff);
		return strtod(buff,NULL); /*!< strtod gives better control of undefined range */
	}
	else
	{
		debugMsg("=============================\r\n");
		debugVal("%s not found\r\n",searchString);
		debugMsg("=============================\r\n");
		return -200;
	}
}