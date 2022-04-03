#define _WIN32_WINNT 0x501

/*
VulnServer - a deliberately vulnerable threaded TCP server application

This is vulnerable software, don't run it on an important system!  The author assumes no responsibility if 
you run this software and your system gets compromised, because this software was designed to be exploited!

Visit my blog for more details: http://www.thegreycorner.com
*/


/*
Copyright (c) 2010, Stephen Bradshaw
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define VERSION "1.00"
#define DEFAULT_BUFLEN 4096
#define DEFAULT_PORT "9999"

#define MAX_CLIENTS 100

void Function1(char *Input);
void Function2(char *Input);
void Function3(char *Input);
void Function4(char *Input);
DWORD WINAPI ConnectionHandler(LPVOID CSocket);
void EssentialFunc1();


/* Client structure */
typedef struct {
    struct sockaddr_in addr; /* Client remote address */
    SOCKET connfd;              /* Connection file descriptor */
    int uid;                 /* Client unique identifier */
	char name[32];           /* Client name */
} client_t;

static client_t *clients[MAX_CLIENTS];
int uid = 10;
unsigned int cli_count = 0;

bool MITM=false;

HANDLE ghMutex;

/* Add client to queue */
void queue_add(client_t *cl){
	DWORD dwWaitResult; 
	
	dwWaitResult=WaitForSingleObject(
		ghMutex, 	// handle to mutex
		INFINITE);	// no time-out interval

    switch (dwWaitResult) {
        case WAIT_OBJECT_0: 
            printf("Obtained ghMutex\n");
//           __try { 
				cli_count++;
				printf("A new client just came. %d clients now\n", cli_count);
				for (int i = 0; i < MAX_CLIENTS; ++i) {
					if (!clients[i]) {
						clients[i] = cl;
						break;
					}
				}

//            __finally { 
                // Release ownership of the mutex object
                if (! ReleaseMutex(ghMutex)) 
                { 
                    printf("ReleaseMutex wrong\n");    // Handle error.
                } else {
					printf("ReleaseMutex right\n");
				}
//            } 
            break; 


            // The thread got ownership of an abandoned mutex
            // An indeterminate state
        case WAIT_ABANDONED: 
			printf("WAIT_ABANDONED\n");
            return; 
	}
	printf("Done with queue_add\n");
}

/* Delete client from queue */
void queue_delete(client_t *cl){
	DWORD dwWaitResult; 

	dwWaitResult=WaitForSingleObject(
		ghMutex, 	// handle to mutex
		INFINITE);	// no time-out interval

    switch (dwWaitResult) 
    {
		// The thread got ownership of the mutex
        case WAIT_OBJECT_0: 
            printf("Obtained ghMutex\n");  
//           __try { 
				cli_count--;
				printf("A client just left. %d clients now\n", cli_count);
				for (int i = 0; i < MAX_CLIENTS; ++i) {
					if (clients[i]) {
						if (clients[i]->uid == cl->uid) {
							clients[i] = NULL;
							break;
						}
					}
				}
				free(cl);
//			}

//            __finally { 
                // Release ownership of the mutex object
                if (! ReleaseMutex(ghMutex)) 
                { 
                    printf("ReleaseMutex wrong\n");    // Handle error.
                } else {
					printf("ReleaseMutex right\n");
				}
//            } 
            break; 


            // The thread got ownership of an abandoned mutex
            // An indeterminate state
        case WAIT_ABANDONED: 
			printf("WAIT_ABANDONED\n");
            return; 
	}
//    pthread_mutex_unlock(&clients_mutex);
	printf("Done with queue_delete\n");

}


/* Broadcast message to current clients */
int broadcast(char *KnocBuf, client_t *pCli){
	DWORD dwWaitResult; 
	int Result, SendResult=-1;
	
	dwWaitResult=WaitForSingleObject(
		ghMutex, 	// handle to mutex
		INFINITE);	// no time-out interval

    switch (dwWaitResult) {
        case WAIT_OBJECT_0: 
            printf("Obtained ghMutex\n");
//           __try { 
				Result=strlen(KnocBuf);

				for (int i = 0; i < MAX_CLIENTS; ++i) {
					if (clients[i]) {
						if (clients[i]->uid != pCli->uid) {
							SendResult = send( clients[i]->connfd, KnocBuf, Result, 0 );
						}
					}
				}

//            __finally { 
                // Release ownership of the mutex object
                if (! ReleaseMutex(ghMutex)) 
                { 
                    printf("ReleaseMutex wrong\n");    // Handle error.
                } else {
					printf("ReleaseMutex right\n");
				}
//            } 
            break; 


            // The thread got ownership of an abandoned mutex
            // An indeterminate state
        case WAIT_ABANDONED: 
			printf("WAIT_ABANDONED\n");
            break; 
	}
	printf("Done with broadcast\n");
	return SendResult;
}


/* Check if there is vacancy */
bool checkVacancy(){
	DWORD dwWaitResult; 
	bool hasVacancy=FALSE;
	
	dwWaitResult=WaitForSingleObject(
		ghMutex, 	// handle to mutex
		INFINITE);	// no time-out interval

    switch (dwWaitResult) {
        case WAIT_OBJECT_0: 
            printf("Obtained ghMutex\n");
//           __try { 
				if (cli_count < MAX_CLIENTS)
					hasVacancy=TRUE;
				else
					hasVacancy=FALSE;

//            __finally { 
                // Release ownership of the mutex object
                if (! ReleaseMutex(ghMutex)) 
                { 
                    printf("ReleaseMutex wrong\n");    // Handle error.
                } else {
					printf("ReleaseMutex right\n");
				}
//            } 
            break; 

            // The thread got ownership of an abandoned mutex
            // An indeterminate state
        case WAIT_ABANDONED: 
			printf("WAIT_ABANDONED\n");
	}
	
	printf("Done with checkVacancy\n");
	return hasVacancy;
}

/*
static int end_flag = 0;

BOOL WINAPI controlHandler(DWORD type){
    if(type == CTRL_C_EVENT){
        end_flag = 1;
        return TRUE;
    }
    return FALSE;
}
*/

int main( int argc, char *argv[] ) {
	char PortNumber[6];
	const char Usage[94] = "Usage: %s [port_number]\n\nIf no port number is provided, the default port of %s will be used.\n";
	if ( argc > 2) {
		printf(Usage, argv[0], DEFAULT_PORT);
		return 1;
	} else if ( argc == 2 ) {
		if ( (atoi(argv[1]) > 0) && (atoi(argv[1]) < 65536) && (strlen(argv[1]) < 7) ) {
			strncpy(PortNumber, argv[1], 6);
		} else {
			printf(Usage, argv[0], DEFAULT_PORT);
			return 1;
		}
	} else {		
		strncpy(PortNumber, DEFAULT_PORT, 6);
	}
	
	///////////////////////////////////////////////////////
	//// Disable quick-edit mode which stalks the program
	///////////////////////////////////////////////////////
	DWORD prev_mode;
	HANDLE hInput=GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(hInput, &prev_mode); 
	SetConsoleMode(hInput, ENABLE_EXTENDED_FLAGS | (prev_mode & ~ENABLE_QUICK_EDIT_MODE));
	
	
	printf("Starting vulnserver version %s\n", VERSION);
	EssentialFunc1(); // Call function from external dll
	printf("\nThis is vulnerable software!\nDo not allow access from untrusted systems or networks!\n\n");
	
	WSADATA wsaData;
	SOCKET ListenSocket = INVALID_SOCKET,
	ClientSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL, hints;
	int Result;
	struct sockaddr_in ClientAddress;
	int ClientAddressL = sizeof(ClientAddress);
	
    ghMutex = CreateMutex( 
        NULL,              // default security attributes
        FALSE,             // initially not owned
        NULL);             // unnamed mutex

    if (ghMutex == NULL) {
        printf("CreateMutex error: %d\n", GetLastError());
        return 1;
    }

	Result = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (Result != 0) {
		printf("WSAStartup failed with error: %d\n", Result);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	Result = getaddrinfo(NULL, PortNumber, &hints, &result);
	if ( Result != 0 ) {
		printf("Getaddrinfo failed with error: %d\n", Result);
		WSACleanup();
		return 1;
	}

	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("Socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	Result = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (Result == SOCKET_ERROR) {
		printf("Bind failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	Result = listen(ListenSocket, SOMAXCONN);
	if (Result == SOCKET_ERROR) {
		printf("Listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}		
/*	
    if (!SetConsoleCtrlHandler(controlHandler, TRUE)) {
        fprintf(stderr, "Failed SetConsoleCtrlHandler");
        return -1;
    }
	while(!end_flag) {	
*/	
	while(1) {	
		printf("Waiting for client connections...\n");

		ClientSocket = accept(ListenSocket, (SOCKADDR*)&ClientAddress, &ClientAddressL);
		if (ClientSocket == INVALID_SOCKET) {
			printf("Accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		} 

		printf("Received a client connection from %s:%u\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port));

        /* Check if max clients is reached */
        if (!checkVacancy()) {
            printf("<< max clients reached\n");
            printf("<< reject ");
            printf("\n");
            closesocket(ClientSocket);
            continue;
        }

        /* Client settings */
        client_t *cli = (client_t *)malloc(sizeof(client_t));
        cli->addr = ClientAddress;
        cli->connfd = ClientSocket;
        cli->uid = uid++;
		sprintf(cli->name, "%d", cli->uid);

		printf("To CreateThread\n");
		CreateThread(0,0,ConnectionHandler, (LPVOID)cli, 0,0);
		
//		Sleep(1000);
		
	}

	///////////////////////////////////////////////////////////////////////////////////
	// Really not useful right now since we have infinite loop that cannot be stopped
	///////////////////////////////////////////////////////////////////////////////////
	closesocket(ListenSocket);
	WSACleanup();
	CloseHandle(ghMutex);

	// Restore previous console mode
	SetConsoleMode(hInput, prev_mode);

	return 0;
}


void Function1(char *Input) {
	char Buffer2S[140];
	strcpy(Buffer2S, Input);
}

void Function2(char *Input) {
	char Buffer2S[60];
	strcpy(Buffer2S, Input);
}

void Function3(char *Input) {
	char Buffer2S[2000];	
	strcpy(Buffer2S, Input);
}

void Function4(char *Input) {
	char Buffer2S[1000];
	strcpy(Buffer2S, Input);
}


DWORD WINAPI ConnectionHandler(LPVOID cli) {
	int RecvBufLen = DEFAULT_BUFLEN;
	char *RecvBuf = malloc(DEFAULT_BUFLEN);
	char BigEmpty[1000];
	char *GdogBuf = malloc(1024);
	int Result, SendResult, i, k;
	client_t *pCli=(client_t * )cli;
	
    queue_add(pCli);
		
	memset(BigEmpty, 0, 1000);
	memset(RecvBuf, 0, DEFAULT_BUFLEN);
	SOCKET Client= pCli->connfd;
//	SOCKET Client = CSocket; 
	
	SendResult = send( Client, "Welcome to Vulnerable Server! Enter HELP for help.\n", 51, 0 );
	sprintf(BigEmpty, "You are User %s.\n", pCli->name);
	SendResult = send( Client, BigEmpty, strlen(BigEmpty)+1, 0 );
	memset(BigEmpty, 0, 1000);
	
	if (SendResult == SOCKET_ERROR) {
		printf("Send failed with error: %d\n", WSAGetLastError());
		closesocket(Client);
		return 1;
	}
	
	while (cli) {
		Result = recv(Client, RecvBuf, RecvBufLen, 0);
		if (Result > 0) {
			if (strncmp(RecvBuf, "HELP ", 5) == 0) {
				const char NotImplemented[47] = "Command specific help has not been implemented\n";
				SendResult = send( Client, NotImplemented, sizeof(NotImplemented), 0 );
			} else if (strncmp(RecvBuf, "HELP", 4) == 0) {
				const char ValidCommands[251] = "Valid Commands:\nHELP\nSTATS [stat_value]\nRTIME [rtime_value]\nLTIME [ltime_value]\nSRUN [srun_value]\nTRUN [trun_value]\nGMON [gmon_value]\nGDOG [gdog_value]\nKSTET [kstet_value]\nGTER [gter_value]\nHTER [hter_value]\nLTER [lter_value]\nKSTAN [lstan_value]\nEXIT\n";
				SendResult = send( Client, ValidCommands, sizeof(ValidCommands), 0 );
			} else if (strncmp(RecvBuf, "STATS ", 6) == 0) {
				char *StatBuf = malloc(120);
				memset(StatBuf, 0, 120);
				strncpy(StatBuf, RecvBuf, 120);
				SendResult = send( Client, "STATS VALUE NORMAL\n", 19, 0 );
			} else if (strncmp(RecvBuf, "RTIME ", 6) == 0) {
				char *RtimeBuf = malloc(120);
				memset(RtimeBuf, 0, 120);
				strncpy(RtimeBuf, RecvBuf, 120);
				SendResult = send( Client, "RTIME VALUE WITHIN LIMITS\n", 26, 0 );
			} else if (strncmp(RecvBuf, "LTIME ", 6) == 0) {
				char *LtimeBuf = malloc(120);
				memset(LtimeBuf, 0, 120);
				strncpy(LtimeBuf, RecvBuf, 120);
				SendResult = send( Client, "LTIME VALUE HIGH, BUT OK\n", 25, 0 );
			} else if (strncmp(RecvBuf, "SRUN ", 5) == 0) {
				char *SrunBuf = malloc(120);
				memset(SrunBuf, 0, 120);
				strncpy(SrunBuf, RecvBuf, 120);
				SendResult = send( Client, "SRUN COMPLETE\n", 14, 0 );
			} else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);				
						Function3(TrunBuf);
						break;
					}
				}
				memset(TrunBuf, 0, 3000);				
				SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
			} else if (strncmp(RecvBuf, "KNOCK ", 6) == 0) {
				////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////
				// Chat server is implemented here /////////////////////////////
				////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////
				char *KnocBuf = malloc(3000);
				memset(KnocBuf, 0, 3000);
				for (i = 6; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(KnocBuf, RecvBuf, 3000);				
						Function3(KnocBuf);
						break;
					}
				}
				memset(KnocBuf, 0, 3000);
				
				RecvBuf[Result]='\0';
				sprintf(KnocBuf, "%s", RecvBuf+6);
				
				// If MITM attack is enabled, add some junk to the message
				if (MITM) {
					char MITMStr[]=" hahaha...";
					sprintf(KnocBuf, "%s %s", RecvBuf+6, MITMStr);
					printf("RecvBuf=%s\n", KnocBuf);
				}

				broadcast(KnocBuf, pCli);
				
				free(KnocBuf);
				////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////
				
			} else if (strncmp(RecvBuf, "MITM ", 5) == 0) {
				// Admin to set MITM /////////////////////////////////////////////
				if ((char)RecvBuf[5] == '1') {
					MITM=true;
				} if ((char)RecvBuf[5] == '0') {
					MITM=false;
				}
			} else if (strncmp(RecvBuf, "NAME ", 5) == 0) {
				// Change name /////////////////////////////////////////////
				memcpy(pCli->name, RecvBuf+5, Result-5);
				// printf("Name changed to %s, length=%d\n", pCli->name, strlen(pCli->name));
				pCli->name[Result-5-2]='\0';
				// printf("Name changed to %s, length=%d\n", pCli->name, strlen(pCli->name));
			} else if (strncmp(RecvBuf, "GMON ", 5) == 0) {
				char GmonStatus[13] = "GMON STARTED\n";
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '/') {
						if (strlen(RecvBuf) > 3950) {
							Function3(RecvBuf);
						}
						break;
					}
				}				
				SendResult = send( Client, GmonStatus, sizeof(GmonStatus), 0 );
			} else if (strncmp(RecvBuf, "GDOG ", 5) == 0) {				
				strncpy(GdogBuf, RecvBuf, 1024);
				SendResult = send( Client, "GDOG RUNNING\n", 13, 0 );
			} else if (strncmp(RecvBuf, "KSTET ", 6) == 0) {
				char *KstetBuf = malloc(100);
				strncpy(KstetBuf, RecvBuf, 100);
				memset(RecvBuf, 0, DEFAULT_BUFLEN);
				Function2(KstetBuf);
				SendResult = send( Client, "KSTET SUCCESSFUL\n", 17, 0 );
			} else if (strncmp(RecvBuf, "GTER ", 5) == 0) {
				char *GterBuf = malloc(180);
				memset(GdogBuf, 0, 1024);
				strncpy(GterBuf, RecvBuf, 180);				
				memset(RecvBuf, 0, DEFAULT_BUFLEN);
				Function1(GterBuf);
				SendResult = send( Client, "GTER ON TRACK\n", 14, 0 );
			} else if (strncmp(RecvBuf, "HTER ", 5) == 0) {
				char THBuf[3];
				memset(THBuf, 0, 3);
				char *HterBuf = malloc((DEFAULT_BUFLEN+1)/2);
				memset(HterBuf, 0, (DEFAULT_BUFLEN+1)/2);
				i = 6;
				k = 0;
				while ( (RecvBuf[i]) && (RecvBuf[i+1])) {
					memcpy(THBuf, (char *)RecvBuf+i, 2);
					unsigned long j = strtoul((char *)THBuf, NULL, 16);
					memset((char *)HterBuf + k, (byte)j, 1);
					i = i + 2;
					k++;
				} 
				Function4(HterBuf);
				memset(HterBuf, 0, (DEFAULT_BUFLEN+1)/2);
				SendResult = send( Client, "HTER RUNNING FINE\n", 18, 0 );
			} else if (strncmp(RecvBuf, "LTER ", 5) == 0) {
				char *LterBuf = malloc(DEFAULT_BUFLEN);
				memset(LterBuf, 0, DEFAULT_BUFLEN);
				i = 0;
				while(RecvBuf[i]) {
					if ((byte)RecvBuf[i] > 0x7f) {
						LterBuf[i] = (byte)RecvBuf[i] - 0x7f;
					} else {
						LterBuf[i] = RecvBuf[i];
					}
					i++;
				}
				for (i = 5; i < DEFAULT_BUFLEN; i++) {
					if ((char)LterBuf[i] == '.') {					
						Function3(LterBuf);
						break;
					}
				}
				memset(LterBuf, 0, DEFAULT_BUFLEN);
				SendResult = send( Client, "LTER COMPLETE\n", 14, 0 );
			} else if (strncmp(RecvBuf, "KSTAN ", 6) == 0) {
				SendResult = send( Client, "KSTAN UNDERWAY\n", 15, 0 );
			} else if (strncmp(RecvBuf, "EXIT", 4) == 0) {
				SendResult = send( Client, "GOODBYE\n", 8, 0 );
				printf("Connection closing...\n");
				break; // Connection exits
			} else {
				SendResult = send( Client, "UNKNOWN COMMAND\n", 16, 0 );
			}
			
			if (SendResult == SOCKET_ERROR) {
				printf("Send failed with error: %d\n", WSAGetLastError());
				break;
			}
		} else if (Result == 0) {
			// If the connection has been gracefully closed, the return value is zero.
			printf("Connection closing...\n");
			break;			
		} else  {
			// Otherwise, a value of SOCKET_ERROR is returned, 
			// and a specific error code can be retrieved by calling WSAGetLastError.
			printf("Recv failed with error: %d\n", WSAGetLastError());
			break;
		}

	}
	
	// The connection is closing for whatever reason
	// Let's clean up
	queue_delete(pCli); // Only deleted from the queue; Socket is not closed

	closesocket(Client); 
	free(RecvBuf);
	free(GdogBuf);
}

