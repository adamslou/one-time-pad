/*******************************************************************************
** Program name: otp_d.c
** Author:       Louis Adams
** Email:        adamslou@oregonstate.edu
** Due date:     2020-06-05     		             	
** Description:  This program is a server which is meant to be run in the background.
**               otp_d stands for One Time Pad Daemon. Its function is to receive
**               encrypted data (a ciphertext) and to send it back when requested.
**               Sockets are used to communicate with the otp program (the client).
**               otp will connect with otp_d in 'get' mode or 'post' mode. If connected
**               in 'get' mode then otp_d will retrieve a user's ciphertext and send
**               it back if one exists. If connected in 'post' mode then otp_d will
**               take the username and ciphertext sent from otp and write the ciphertext
**               to a file. otp_d can accept up to 5 concurrent connections. The parent
**               will continue listening for connections and accept only if there are
**               currently less than 5. Once a connection is made, a child is forked
**               off to handle the 'get' or 'post'. If there is an error in a child
**               process it will exit, but the parent will continue running. When a
**               child terminates, a signal handler for SIGCHLD will immediately reap
**               the zombie child process, and decrement the global counter.
*******************************************************************************/ 
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

// function prototypes:
bool sendAll(int socket, void* buffer, size_t length);
bool recvAll(int socket, void* buffer, size_t length);
void catchSIGCHLD(int signo);

// error function used for reporting issues
void error(const char *msg) { perror(msg); exit(1); }
    
// global variable
int numChildPids = 0;                   // the number of child processes spawned

int main(int argc, char *argv[]){
    int listenSocketFD, establishedConnectionFD, portNumber;
    socklen_t sizeOfClientInfo;
    char* ciphertext = NULL;            // a buffer for the ciphertext we receive from otp
    char* user = NULL;                  // a buffer for the username we receive from otp
    char* infix = "@cipher";            // to be inserted into the middle of a ciphertext filename
    size_t ciphertextSize;              // the size of the ciphertext (unsigned)
    size_t ciphertextBuffSize;          // the size of the ciphertext buffer used with getline()
    ssize_t sCiphertextSize;            // the size of the ciphertext (signed), used with getline()
    size_t userSize;                    // the size of the username sent from otp
    char mode;                          // equals 'g' for get or 'p' for post
    bool foundUserFile = false;         // true if we've found a ciphertext file for the given user
    pid_t spawnPid;                     // the return value of a fork() call
    pid_t pid;                          // the pid of a child process to be used for a filename
    FILE* file;                         // declare FILE pointer for the ciphertext file
    DIR* dir;                           // declare DIR pointer
    char filename[50];                  // the name of a file which contains ciphertext
    struct dirent* dirEnt;              // pointer for directory entry
    struct stat dirInfo;                // contains info about a directory
    char oldestFile[50];                // the name of the oldest ciphertext file for a user
    int statReturnVal;                  // this is 1 or 0 depending on if the stat call was successful
    int timeDiff;                       // difference between the time a file was modified and the current runtime
    time_t time1970;                    // seconds elapsed since 1970
    int oldestTime = 0;                 // the oldest time will be the greatest time difference

    if(argc < 2) { fprintf(stderr,"otp_d USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

    // instantiate sigaction struct: parent will use SIGCHLD_action
    struct sigaction SIGCHLD_action = {{0}};
    
    // parent will use the catchSIGCHLD signal handler function to catch SIGCHLD, use SA_NOCLDSTOP
    // so that SIGCHLD won't be raised if a child process stops or continues, only if it terminates
    SIGCHLD_action.sa_handler = catchSIGCHLD;
    sigfillset(&SIGCHLD_action.sa_mask);
    SIGCHLD_action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    
    // parent uses the handler catchSIGCHLD to reap zombie children
    sigaction(SIGCHLD, &SIGCHLD_action, NULL);

    // Set up the address struct for this process (the server)
    struct sockaddr_in serverAddress, clientAddress;
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[1]);                 // Get the port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET;         // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber); // Store the port number
    serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

    // Set up the socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if(listenSocketFD < 0) error("otp_d ERROR opening socket");

    // Enable the socket to begin listening and connect to the port
    if(bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        error("otp_d ERROR on binding");
    listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

    while(true){
        // keep accepting connections as long as there are less than 5 concurrent processes running
        if(numChildPids < 5){
            // get the size of the address for the client that will connect
            sizeOfClientInfo = sizeof(clientAddress);

            // accept a connection, blocking if one is not available until one connects
            establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
            if(establishedConnectionFD < 0) perror("otp_d ERROR on accept");

            // fork off a child process for each connection up to 5 connections
            spawnPid = -5;
            spawnPid = fork();
            if(spawnPid == -1){
                perror("otp_d ERROR spawning child process");
            }

            if(spawnPid == 0){
                // this is the child
                // sleep for 2 seconds
                sleep(2);

                // get the mode from otp
                if(!recvAll(establishedConnectionFD, &mode, sizeof(char))){
                    error("otp_d ERROR reading from socket");
                }

                // get the size of the username to be sent from otp
                if(!recvAll(establishedConnectionFD, &userSize, sizeof(size_t))){
                    error("otp_d ERROR reading from socket");
                }

                // allocate memory on the heap for the username
                user = malloc((userSize + 1) * sizeof(char));
                if(user == NULL) error("otp_d ERROR with malloc");

                // get the username from otp
                if(!recvAll(establishedConnectionFD, user, userSize)){
                    error("otp_d ERROR reading from socket");
                }
                user[userSize] = '\0';

                // 'post' mode
                if(mode == 'p'){
                    // get the size of the ciphertext to be sent from otp
                    if(!recvAll(establishedConnectionFD, &ciphertextSize, sizeof(size_t))){
                        error("otp_d ERROR reading from socket");
                    }

                    // allocate memory on the heap for the ciphertext
                    ciphertext = malloc((ciphertextSize + 1) * sizeof(char));
                    if(ciphertext == NULL) error("otp_d ERROR on malloc");

                    // get the ciphertext from otp
                    if(!recvAll(establishedConnectionFD, ciphertext, ciphertextSize)){
                        error("otp_d ERROR reading from socket");
                    }
                    ciphertext[ciphertextSize] = '\0';

                    // write the ciphertext to a file
                    pid = getpid();                                 // get process id of the child
                    snprintf(filename, 50, "%s%s%d", user, infix, pid);// create filename with user, infix, & pid
                    file = fopen(filename, "w");                    // open the file for writing
                    if(!file){
                        error("otp_d ERROR opening file");
                    }
                    fprintf(file, "%s\n", ciphertext);  // write the ciphertext + newline to the file
                    fclose(file);                       // close the file

                    // print the path to the file
                    printf("%s\n", filename);
                    fflush(stdout);
                }
                // 'get' mode
                else{
                    // open the current directory and get pointer of type DIR
                    dir = opendir(".");
                    if(dir == NULL){        // opendir returns NULL if we can't open directory
                        error("otp_d ERROR opening current directory");
                    }

                    // find the oldest ciphertext file for the user
                    time1970 = time(NULL);  // get seconds elapsed since 1970
                    while((dirEnt = readdir(dir)) != NULL){
                        // examine files that contain the username and the infix
                        if(strstr(dirEnt->d_name, user) != NULL && strstr(dirEnt->d_name, infix) != NULL){
                            statReturnVal = stat(dirEnt->d_name, &dirInfo); // put info on a file into dirInfo
                            if(statReturnVal != 0){
                                error("otp_d ERROR using stat() on rooms directory");
                            }

                            // find the greatest time difference between the current time (immediately
                            // before looping through the user's files) and time of the most recent
                            // modification to the file, this will give us the oldest file
                            timeDiff = difftime(time1970, dirInfo.st_mtime);
                            if(timeDiff > oldestTime){
                                oldestTime = timeDiff;
                                strcpy(oldestFile, dirEnt->d_name);
                            }

                            // we've found a ciphertext file for the given user
                            foundUserFile = true;
                        }
                    }

                    // send 's' for success if we've found a ciphertext file for the user
                    if(foundUserFile == true){
                        if(!sendAll(establishedConnectionFD, "s", sizeof(char))){
                            error("otp_d ERROR writing to socket");
                        }
                    }
                    // otherwise, send 'f' for failure if the user doesn't have a ciphertext file
                    else{
                        if(!sendAll(establishedConnectionFD, "f", sizeof(char))){
                            error("otp_d ERROR writing to socket");
                        }
                        exit(1);    // child exits if the given user doesn't have a ciphertext file
                    }

                    // open the user's oldest file for reading
                    file = fopen(oldestFile, "r");
                    if(!file){
                        error("otp_d ERROR opening file");
                    }
                    
                    // get the ciphertext from the file (which should be 1 line)
                    sCiphertextSize = getline(&ciphertext, &ciphertextBuffSize, file);
                    if(sCiphertextSize < 0){
                        error("otp_d ERROR getting ciphertext with getline()");
                    }
                    // convert signed (sCiphertextSize) to unsigned (ciphertextSize) since we know it's positive
                    ciphertextSize = sCiphertextSize;

                    // strip off newline character and decrement size by 1
                    ciphertext[ciphertextSize - 1] = '\0';
                    ciphertextSize--;

                    // check ciphertext for bad characters
                    for(int i = 0; i < ciphertextSize; i++){
                        if((ciphertext[i] < 65 || ciphertext[i] > 90) && ciphertext[i] != 32){
                            fprintf(stderr, "otp_d ERROR: \"%s\" has bad characters\n", oldestFile);
                            exit(1);
                        }
                    }
                    
                    // send size of the ciphertext to otp
                    if(!sendAll(establishedConnectionFD, &ciphertextSize, sizeof(size_t))){
                        error("otp_d ERROR writing to socket");
                    }

                    // send the ciphertext back to otp
                    if(!sendAll(establishedConnectionFD, ciphertext, ciphertextSize)){
                        error("otp_d ERROR writing to socket");
                    }
                   
                    // remove the ciphertext file once we've read and sent its contents
                    fclose(file);                       // close the file
                    remove(oldestFile);
                }

                // child processes free memory they've allocated on the heap
                free(ciphertext);
                free(user);

                // child processes close the established connection corresponding with themselves
                close(establishedConnectionFD);

                // child exits normally
                exit(0);
            }
            else{
                // this is the parent
                numChildPids++;     // increment the # of child processes currently running
            }
        }
    }// end of while loop

    // parent closes the listening socket
    close(listenSocketFD);

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

/*******************************************************************************
 *                                  catchSIGCHLD                               *
 * This function catches SIGCHLD signals and waits for the terminated child    *
 * processes in order to reap these zombies. It also importantly decrements    *
 * the number of child processes currently running which is important for      *
 * allowing 5 concurrent child processes to run at any given time.             *
 ******************************************************************************/
void catchSIGCHLD(int signo){
    int status;

    // continue waiting for child processes not yet terminated as long as waitpid is returning
    // a value > 0 (which would be a child pid), this is in case another child process
    // terminates while we're in the sig handler, use WNOHANG so we're not blocking
    while(waitpid(-1, &status, WNOHANG) > 0){
        // decrement the number of child processes running once we've waited for a terminated one
        numChildPids--;
    }
}
