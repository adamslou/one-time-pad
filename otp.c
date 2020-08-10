/*******************************************************************************
** Program name: otp.c
** Author:       Louis Adams
** Email:        adamslou@oregonstate.edu
** Due date:     2020-06-05     		             	
** Description:  This program is a client which will connect with the otp_d (server)
**               program. It should be ran with either a 'get' or 'post' argument
**               like this:     otp get username key port#
**                              otp post username plaintextfile key port#
**               If run in 'post' mode, a plaintext file will be converted into a
**               ciphertext using a key (generated with the keygen program). Then
**               the ciphertext will be sent to otp_d through a socket connection
**               for storage. If run in 'get' mode then the username will be sent
**               to otp_d and otp_d will search for the oldest ciphertext file for
**               that user and send back the ciphertext, and then delete the ciphertext.
**               otp will then use the key given by the user and convert the ciphertext
**               to plaintext. If the user provided the wrong key, the ciphertext
**               will not be deciphered correctly but will still be deleted. It's
**               only for one-time use! Once otp has converted the ciphertext to
**               plaintext using the key, the plaintext will be output to the console.
*******************************************************************************/ 
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

// function prototypes:
bool sendAll(int socket, void* buffer, size_t length);
bool recvAll(int socket, void* buffer, size_t length);

void error(const char *msg) { perror(msg); exit(1); } // error function used for reporting issues

int main(int argc, char *argv[]){
    int socketFD, portNumber;
    struct sockaddr_in serverAddress;
    struct hostent* serverHostInfo;
    char* plaintext = NULL;         // a buffer for the plaintext to be read from a file
    char* key = NULL;               // a buffer for the key to be read from a file
    char* ciphertext = NULL;        // a buffer for the ciphertext to be sent to otp_d
    char userFileResult;            // will contain 's' if the user has a ciphertext file, otherwise 'f'
    size_t userSize = strlen(argv[2]);  // size of the username
    size_t plaintextBuffSize;       // size of the plaintext buffer used with getline()
    size_t keyBuffSize;             // size of the key buffer used with getline()
    size_t ciphertextSize;          // size of the ciphertext
    size_t plaintextSize;           // size of the plaintext (unsigned)
    size_t keySize;                 // size of the key (unsigned)
    ssize_t sPlaintextSize;         // size of the plaintext (signed), used with getline()
    ssize_t sKeySize;               // size of the key, (signed), used with getline()
    FILE* plaintextFile;            // declare FILE pointer to the plaintext file
    FILE* keyFile;                  // declare FILE pointer to the key file
    bool postMode;                  // true if user entered "post"

    // determine if "get" or "post" was entered
    if(strcmp(argv[1], "post") == 0){
        postMode = true;
    }
    else if(strcmp(argv[1], "get") == 0){
        postMode = false;
    }
    else{
        error("otp ERROR, user must enter \"get\" or \"post\" as argv[1]");
    }

    // if we are in post mode, we get the plaintext and key and create the ciphertext
    if(postMode == true){
        // check for the correct number of arguments
        if(argc < 6){ 
            fprintf(stderr,"otp USAGE: %s post user plaintext key port\n", argv[0]); exit(1);
        }

        // get plaintext to be encrypted
        plaintextFile = fopen(argv[3], "r");
        if(!plaintextFile){
            error("otp ERROR opening plaintext file\n");
        }

        // get key to encrypt plaintext with
        keyFile = fopen(argv[4], "r");
        if(!keyFile){
            error("otp ERROR opening key file\n");
        }

        // get the text from the plaintext file, which should be 1 line
        sPlaintextSize = getline(&plaintext, &plaintextBuffSize, plaintextFile);
        if(sPlaintextSize < 0){
            error("otp ERROR getting plaintext with getline()\n");
        }
        // convert sPlaintextSize (signed) to plaintextSize (unsigned) since we know it's positive
        plaintextSize = sPlaintextSize;

        // get the text from the key file, which should be 1 line
        sKeySize = getline(&key, &keyBuffSize, keyFile);
        if(sKeySize < 0){
            error("otp ERROR getting key with getline()\n");
        }
        // convert sKeySize (signed) to keySize (unsigned) since we know it's positive
        keySize = sKeySize;
        if(keySize < plaintextSize){
            fprintf(stderr, "otp ERROR: \"%s\" not long enough for \"%s\"\n", argv[4], argv[3]);
            exit(1);
        }

        // strip off newline characters and decrement size by 1
        plaintext[plaintextSize - 1] = '\0';
        key[keySize - 1] = '\0';
        plaintextSize--;
        keySize--;

        // check plaintext and key for bad characters
        for(int i = 0; i < plaintextSize; i++){
            if((plaintext[i] < 65 || plaintext[i] > 90) && plaintext[i] != 32){
                fprintf(stderr, "otp ERROR: \"%s\" has bad characters\n", argv[3]);
                exit(1);
            }
        }
        for(int i = 0; i < keySize; i++){
            if((key[i] < 65 || key[i] > 90) && key[i] != 32){
                fprintf(stderr, "otp ERROR: \"%s\" has bad characters\n", argv[4]);
                exit(1);
            }
        }

        // allocate memory on the heap for the ciphertext, add 1 to the size for the null terminator
        ciphertext = malloc((plaintextSize + 1) * sizeof(char));
        if(ciphertext == NULL) error("otp ERROR on malloc");
        ciphertext[plaintextSize] = '\0';
        ciphertextSize = plaintextSize;

        // create ciphertext from the plaintext and the key
        // we have 27 possible values with the space being value 0 and the uppercase letters A-Z being 1-26
        // instead of using the values 0-26, we'll use ASCII values 65-90 representing letters A-Z and we'll 
        // treat the space as if it comes before the letters (ASCII 64), so we're using the values 64-90
        for(int i = 0; i < plaintextSize; i++){
            if(key[i] == 32){       // if the key is a space, the ciphertext will equal the plaintext
                ciphertext[i] = plaintext[i];
            }
            else if(plaintext[i] == 32){    // if the plaintext is a space, the ciphertext will equal the key
                ciphertext[i] = key[i];
            }
            else{
                ciphertext[i] = plaintext[i] + key[i] - 64;
                if(ciphertext[i] > 90){
                    ciphertext[i] = ciphertext[i] % 91 + 64;
                }
                if(ciphertext[i] == 64){    // if we get a value of 64, change it to 32 (a space)
                    ciphertext[i] = 32;
                }
            }
        }
    }
    // else we are in get mode
    else{
        // check for the correct number of arguments
        if(argc < 5){ 
            fprintf(stderr,"otp USAGE: %s get user key port\n", argv[0]); exit(1);
        }

        // get key to decrypt ciphertext with
        keyFile = fopen(argv[3], "r");
        if(!keyFile){
            error("otp ERROR opening key file\n");
        }

        // get the text from the key file, which should be 1 line
        sKeySize = getline(&key, &keyBuffSize, keyFile);
        if(sKeySize < 0){
            error("otp ERROR getting key with getline()\n");
        }
        // convert sKeySize (signed) to keySize (unsigned) since we know it's positive
        keySize = sKeySize;

        // strip off newline characters and decrement size by 1
        key[keySize - 1] = '\0';
        keySize--;

        // check key for bad characters
        for(int i = 0; i < keySize; i++){
            if((key[i] < 65 || key[i] > 90) && key[i] != 32){
                fprintf(stderr, "otp ERROR: \"%s\" has bad characters\n", argv[3]);
                exit(1);
            }
        }
    }

    // Set up the server address struct
    memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    // Get the port number, convert to an integer from a string
    if(postMode == true){
        portNumber = atoi(argv[5]);
    }
    else{
        portNumber  = atoi(argv[4]);
    }
    serverAddress.sin_family = AF_INET;         // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber); // Store the port number
    serverHostInfo = gethostbyname("localhost");    // Convert the machine name into a special form of address
    if(serverHostInfo == NULL) { fprintf(stderr, "otp ERROR: no such host\n"); exit(2); }
    
    // Copy in the address
    memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);

    // Set up the socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if(socketFD < 0) error("otp ERROR opening socket");
    
    // Connect to server's address
    if(connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
        fprintf(stderr, "otp ERROR connecting to port %d\n", portNumber); 
        exit(2);
    }

    if(postMode == true){
        // send the mode to otp_d, 'p' is for 'post'
        if(!sendAll(socketFD, "p", sizeof(char))){
            error("otp ERROR writing to socket");
        }

        // send size of the username to otp_d
        if(!sendAll(socketFD, &userSize, sizeof(size_t))){
            error("otp ERROR writing to socket");
        }

        // send the username to otp_d
        if(!sendAll(socketFD, argv[2], userSize)){
            error("otp ERROR writing to socket");
        }

        // send size of the ciphertext to otp_d
        if(!sendAll(socketFD, &ciphertextSize, sizeof(size_t))){
            error("otp ERROR writing to socket");
        }

        // send the ciphertext to otp_d
        if(!sendAll(socketFD, ciphertext, ciphertextSize)){
            error("otp ERROR writing to socket");
        }
    }

    // 'get' mode
    if(postMode == false){
        // send the mode to otp_d, 'g' is for 'get'
        if(!sendAll(socketFD, "g", sizeof(char))){
            error("otp ERROR writing to socket");
        }

        // send size of the username to otp_d
        if(!sendAll(socketFD, &userSize, sizeof(size_t))){
            error("otp ERROR writing to socket");
        }

        // send the username to otp_d
        if(!sendAll(socketFD, argv[2], userSize)){
            error("otp ERROR writing to socket");
        }

        // receive the success 's' or failure 'f' of finding a ciphertext file for the user
        if(!recvAll(socketFD, &userFileResult, sizeof(char))){
            error("otp ERROR reading from socket");
        }
        if(userFileResult == 'f'){
            fprintf(stderr, "otp ERROR: no ciphertext for user \"%s\"\n", argv[2]);
            exit(1);    // exit if the given user has no ciphertext file
        }

        // receive ciphertext size from otp_d
        if(!recvAll(socketFD, &ciphertextSize, sizeof(size_t))){
            error("otp ERROR reading from socket");
        }

        if(keySize < ciphertextSize){
            fprintf(stderr, "otp ERROR: \"%s\" not long enough for the ciphertext\n", argv[3]);
            exit(1);    // exit if the key isn't long enough for the ciphertext
        }

        // allocate memory on the heap for ciphertext and plaintext, add 1 to the size for the null terminator
        ciphertext = malloc((ciphertextSize + 1) * sizeof(char));
        if(ciphertext == NULL) error("otp ERROR on malloc");
        plaintext = malloc((ciphertextSize + 1) * sizeof(char));    // plaintext is the same size as ciphertext
        if(plaintext == NULL) error("otp ERROR on malloc");

        // get the ciphertext from otp
        if(!recvAll(socketFD, ciphertext, ciphertextSize)){
            error("otp ERROR reading from socket");
        }
        ciphertext[ciphertextSize] = '\0';

        // create plaintext from the ciphertext and the key
        // we have 27 possible values with the space being value 0 and the uppercase letters A-Z being 1-26
        // instead of using the values 0-26, we'll use ASCII values 65-90 representing letters A-Z and we'll 
        // treat the space as if it comes before the letters (ASCII 64), so we're using the values 64-90
        for(int i = 0; i < ciphertextSize; i++){
            if(key[i] == 32){       // if the key is a space, the plaintext will equal the ciphertext
                plaintext[i] = ciphertext[i];
            }
            else if(ciphertext[i] == 32){   // if the ciphertext is a space, treat the space as ASCII value 64
                plaintext[i] = 91 - (key[i] - 64);
            }
            else{
                plaintext[i] = ciphertext[i] - key[i] + 64;
                if(plaintext[i] < 64){
                    plaintext[i] = plaintext[i] + 27;
                }
                if(plaintext[i] == 64){     // if we get a value of 64, change it to 32 (a space)
                    plaintext[i] = 32;
                }
            }
        }
        plaintext[ciphertextSize] = '\0';   // add a null terminator to the end of plaintext

        // print the plaintext followed by a newline
        printf("%s\n", plaintext);
        fflush(stdout);
    }

    // free memory allocated by getline() and malloc()
    free(plaintext);
    free(key);
    free(ciphertext);

    // close files
    fclose(keyFile);
    if(postMode == true){
        fclose(plaintextFile);
    }

    // close socket
    close(socketFD);

    return 0;
}

/*******************************************************************************
 *                                  sendAll                                    *
 * This function makes sure all of the data in a buffer is sent. If the        *
 * connection is interrupted, send() will be called again until all the data is*
 * sent, in which case 'true' is returned.                                     *
 * Adapted from:                                                               *
 * https://stackoverflow.com/questions/13479760/c-socket-recv-and-send-all-data
 ******************************************************************************/
bool sendAll(int socket, void* buffer, size_t length){
    char* ptr = (char*)buffer;  // initialize a pointer to the start of the buffer
    
    // once length is 0, all of the data from the buffer has been sent
    while(length > 0){
        ssize_t i = send(socket, ptr, length, 0);
        if(i < 1){
            return false;
        }
        ptr += i;               // move pointer ahead by the number of bytes sent
        length -= i;
    }
    return true;
}

/*******************************************************************************
 *                                  recvAll                                    *
 * This function makes sure all of the data in a buffer is received. If the    *
 * connection is interrupted, recv() will be called again until all the data is*
 * received, in which case 'true' is returned.                                 *
 * Adapted from:                                                               *
 * https://stackoverflow.com/questions/13479760/c-socket-recv-and-send-all-data
 ******************************************************************************/
bool recvAll(int socket, void* buffer, size_t length){
    char* ptr = (char*)buffer;  // initialize a pointer to the start of the buffer
    
    // once length is 0, all of the data from the buffer has been received
    while(length > 0){
        ssize_t i = recv(socket, ptr, length, 0);
        if(i < 1){
            return false;
        }
        ptr += i;               // move pointer ahead by the number of bytes received
        length -= i;
    }
    return true;
}
