all: tunClient tunServer

tapReader: tapReader.c
	gcc -o tunClient tunClient.c

tapServer: tapServer.c
	gcc -o tunServer tunServer.c
