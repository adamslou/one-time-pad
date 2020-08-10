# Program name: makefile
# Author: Louis Adams
# Due Date: 2020-06-05
# Description: This is the makefile for Program 4 - Dead Drop.

CXX = gcc
CXXFLAGS = -std=c99
CXXFLAGS += -Wall
CXXFLAGS += -pedantic-errors
#CXXFLAGS += -g
LDFLAGS = -lboost_date_time

all: keygen otp otp_d

keygen: keygen.c
	${CXX} keygen.c -o keygen ${CXXFLAGS} ${LDFLAGS}
otp: otp.c
	${CXX} otp.c -o otp ${CXXFLAGS} ${LDFLAGS}
otp_d: otp_d.c
	${CXX} otp_d.c -o otp_d ${CXXFLAGS} ${LDFLAGS}

EXECUTABLES = keygen otp otp_d

clean:
	rm -rf ${EXECUTABLES}

zip:
	zip -D Program4_Adams_Louis.zip *.c plaintext* compileall p4gradingscript

val:
	valgrind otp get adamslou file2 6165 --leak-check=full./otp
