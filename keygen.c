/*******************************************************************************
** Program name: keygen.c
** Author:       Louis Adams
** Email:        adamslou@oregonstate.edu
** Due date:     2020-06-05     		             	
** Description:  This program creates a random key to be output to stdout. The
**               key should include only capital letters A-Z as well as space 
**               characters. The key will be of a length specified by arg[1].
**               When output to stdout a newline character will follow the key.
**               The key is meant to used with a plaintext file to create a
**               ciphertext for the otp (One Time Pad) program.
*******************************************************************************/ 
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

int main(int argc, char *argv[]){
    char* endPtr;                           // points to the end of the number entered by the user
    errno = 0;
    int keyLen;                             // the length of the key
    char* key;                              // points to the generated key
    int randNum;                            // a random number from 64-90 representing A-Z or a space

    // seed the random number generator
    srand(time(0));


    // convert argv[1] to an integer
    // adapted from: https://stackoverflow.com/questions/9748393/how-can-i-get-argv-as-int/38669018 
    long keyLenLong = strtol(argv[1], &endPtr, 10);  // convert argument to type long in base 10

    if(errno != 0 || *endPtr != '\0' || keyLenLong > INT_MAX || keyLenLong < 1){
        perror("You must use a positive integer with keygen.\n");
    }
    else{
        keyLen = keyLenLong;
    }

    // allocate memory on the heap for the key
    key = malloc((keyLen + 1) * sizeof(char));  // add 1 to keyLen for the null terminator

    // add random characters to the key
    for(int i = 0; i < keyLen; i++){
        randNum = rand() % 27 + 64;
        if(randNum != 64){  // if the random number equals 65-90, then add the corresponding ASCII character (A-Z)
            key[i] = randNum;
        }
        else{
            key[i] = ' ';   // if the random number equals 64, then add a space to the key
        }
    }

    // add a null terminator to the key string
    key[keyLen] = '\0';

    // print the key followed by a newline character
    printf("%s\n", key);

    // free the memory on the heap
    free(key);

    return 0;
}
