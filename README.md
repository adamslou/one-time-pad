# One Time Pad

keygen creates a random key to be output to stdout. The key includes only capital letters A-Z as well as space characters. The key will be of a length specified by arg[1].
When output to stdout a newline character will follow the key. The key is meant to used with a plaintext file to create a ciphertext for the otp (One Time Pad) program.

otp_d is a server which is meant to be run in the background. otp_d stands for One Time Pad Daemon. Its function is to receive encrypted data (a ciphertext) and to send it back when requested. Sockets are used to communicate with the otp program (the client). otp will connect with otp_d in 'get' mode or 'post' mode. If connected in 'get' mode then otp_d will retrieve a user's ciphertext and send it back if one exists. If connected in 'post' mode then otp_d will take the username and ciphertext sent from otp and write the ciphertext to a file. otp_d can accept up to 5 concurrent connections. The parent will continue listening for connections and accept only if there are currently less than 5. Once a connection is made, a child is forked off to handle the 'get' or 'post'. If there is an error in a child process it will exit, but the parent will continue running. When a child terminates, a signal handler for SIGCHLD will immediately reap the zombie child process, and decrement the global counter.

otp is a client which will connect with the otp_d (server) program. It should be ran with either a 'get' or 'post' argument. If run in 'post' mode, a plaintext file will be converted into a ciphertext using a key (generated with the keygen program). Then the ciphertext will be sent to otp_d through a socket connection for storage. If run in 'get' mode then the username will be sent to otp_d and otp_d will search for the oldest ciphertext file for that user and send back the ciphertext, and then delete the ciphertext. otp will then use the key given by the user and convert the ciphertext to plaintext. If the user provided the wrong key, the ciphertext will not be deciphered correctly but will still be deleted. It's only for one-time use! Once otp has converted the ciphertext to plaintext using the key, the plaintext will be output to the console.

## System Requirements

Linux, gcc, c99+, GNU Make

## Compilation

Use Make to compile: `$ make`

## Usage

First, have a plaintext file that you want to encrypt ready. Then run keygen for a length long enough for your plaintext file. You can get the length of your plaintext by running wc.  Then use keygen to generate a key of that length.
```bash
$ wc -c [plaintextfile]
$ keygen [length] > mykey
```
Then run the daemon on a port of your choice.
```bash
$ otp_d [port#]
```

Then you can send a ciphertext to the daemon for a specified user and plaintext file.
```bash
$ otp post [username] [plaintextfile] [mykey] [port#]
```

Finally, you can get the most recent ciphertext for a specified user. You should also specify the key you want to use to decipher it.
```bash
$ otp get [username] [mykey] [port#]
```
