/*
Kunpeng Zhang (kunpengzhang@email.arizona.edu)
*/

/*
 * udpserver.c - A simple UDP echo server
 * usage: udpserver <port>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/udp.h>

#define BUFSIZE 1024

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

/*
 * error - wrapper for perror
 */
void error(char *msg) {
   perror(msg);
   exit(1);
}

union longchar {
   unsigned char a[5];
   long p;
};
typedef union longchar lchar;

struct QUESTION
{
   unsigned short qtype;
   unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
   unsigned short type;
   unsigned short _class;
   unsigned int ttl;
   unsigned short data_len;
};
#pragma pack(pop)

struct RES_RECORD
{
   unsigned char *name;
   struct R_DATA *resource;
   unsigned char *rdata;
};

struct DNS_HEADER
{
   unsigned short id; // identification number
   
   unsigned char rd :1; // recursion desired
   unsigned char tc :1; // truncated message
   unsigned char aa :1; // authoritive answer
   unsigned char opcode :4; // purpose of message
   unsigned char qr :1; // query/response flag
   
   unsigned char rcode :4; // response code
   unsigned char cd :1; // checking disabled
   unsigned char ad :1; // authenticated data
   unsigned char z :1; // its z! reserved
   unsigned char ra :1; // recursion available
   
   unsigned short q_count; // number of question entries
   unsigned short ans_count; // number of answer entries
   unsigned short auth_count; // number of authority entries
   unsigned short add_count; // number of resource entries
};

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) {
   int lock = 0 , i;
   strcat((char*)host,".");
   
   for(i = 0 ; i < strlen((char*)host) ; i++) {
      if(host[i]=='.') {
         *dns++ = i-lock;
         for(;lock<i;lock++) {
            *dns++=host[lock];
         }
         lock++; //or lock=i+1;
      }
   }
   *dns++='\0';
}


u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
   unsigned char *name;
   unsigned int p=0,jumped=0,offset;
   int i , j;
   
   *count = 1;
   name = (unsigned char*)malloc(256);
   name[0]='\0';
   
   //read the names in 3www6google3com format
   while(*reader!=0) {
      if(*reader>=192) {
         offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
         reader = buffer + offset - 1;
         jumped = 1; //we have jumped to another location so counting wont go up!
      }
      else {
         name[p++]=*reader;
      }
      reader = reader+1;
      if(jumped==0) {
         *count = *count + 1; //if we havent jumped to another location then we can count up
      }
   }
   name[p]='\0'; //string complete
   if(jumped==1) {
      *count = *count + 1; //number of steps we actually moved forward in the packet
   }
   //now convert 3www6google3com0 to www.google.com
   for(i=0;i<(int)strlen((const char*)name);i++) {
      p=name[i];
      for(j=0;j<(int)p;j++) {
         name[i]=name[i+1];
         i=i+1;
      }
      name[i]='.';
   }
   name[i-1]='\0'; //remove the last dot
   return name;
}


int main(int argc, char **argv) {
   int sockfd; /* socket */
   int portno; /* port to listen on */
   int clientlen; /* byte size of client's address */
   struct sockaddr_in serveraddr; /* server's addr */
   struct sockaddr_in clientaddr; /* client addr */
   struct hostent *hostp; /* client host info */
   unsigned char buf[BUFSIZE]; /* message buf */
   char *hostaddrp; /* dotted decimal host addr string */
   int optval; /* flag value for setsockopt */
   int n; /* message byte size */
   
   /*
    * check command line arguments
    */
   if (argc != 2) {
      fprintf(stderr, "usage: %s <port>\n", argv[0]);
      exit(1);
   }
   portno = atoi(argv[1]);
   
   /*
    * socket: create the parent socket
    */
   sockfd = socket(AF_INET, SOCK_DGRAM, 0);
   if (sockfd < 0)
      error("ERROR opening socket");
   
   /* setsockopt: Handy debugging trick that lets
    * us rerun the server immediately after we kill it;
    * otherwise we have to wait about 20 secs.
    * Eliminates "ERROR on binding: Address already in use" error.
    */
   optval = 1;
   setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
              (const void *)&optval , sizeof(int));
   
   /*
    * build the server's Internet address
    */
   bzero((char *) &serveraddr, sizeof(serveraddr));
   serveraddr.sin_family = AF_INET;
   if(inet_aton("127.0.0.1", &(serveraddr.sin_addr)) == 0)
      error("invalid local address");
   serveraddr.sin_port = htons((unsigned short)portno);
   
   /*
    * bind: associate the parent socket with a port
    */
   if (bind(sockfd, (struct sockaddr *) &serveraddr,
            sizeof(serveraddr)) < 0)
      error("ERROR on binding");
   
   /*
    * main loop: wait for a datagram, then echo it
    */
   clientlen = sizeof(clientaddr);
   while (1) {
      
      /*
       * recvfrom: receive a UDP datagram from a client
       */
      bzero(buf, BUFSIZE);
      n = recvfrom(sockfd, buf, BUFSIZE, 0,
                   (struct sockaddr *) &clientaddr, &clientlen);
      if (n < 0)
         error("ERROR in recvfrom");
      
      /*
       * gethostbyaddr: determine who sent the datagram
       */
      hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
                            sizeof(clientaddr.sin_addr.s_addr), AF_INET);
      if (hostp == NULL)
         error("ERROR on gethostbyaddr");
      hostaddrp = inet_ntoa(clientaddr.sin_addr);
      if (hostaddrp == NULL)
         error("ERROR on inet_ntoa\n");
      printf("server received datagram from %s (%s)\n",
             hostp->h_name, hostaddrp);
      printf("server received %d/%d bytes: %s\n", strlen(buf), n, buf);
      
      
      // Read query
      struct DNS_HEADER *dns = NULL;
      unsigned char *writer, *host;
      int stop = 0;
      dns = (struct DNS_HEADER*) buf;
      writer = &buf[sizeof(struct DNS_HEADER)];
      host = ReadName(writer, buf, &stop);
      printf("server2: %s\n", buf);
      printf("server3: %s\n", host);
      
      // information about request
      int recursion_desired;
      recursion_desired=dns->rd;
      unsigned short reqid, qcount;
      reqid = dns->id;
      qcount = ntohs(dns->q_count);
      
      // preparing response
      struct QUESTION *qinfo = NULL;
      unsigned char *qname;
      unsigned int replysize = 0;
      memset(buf,'\0', BUFSIZE);
      dns = (struct DNS_HEADER *)&buf;
      dns->id = reqid;
      dns->qr = 1;
      dns->opcode = 0;
      dns->aa = 0;
      dns->tc = 0;
      dns->rd = 1;
      dns->ra = 1;
      dns->z = 0;
      dns->ad = 0;
      dns->cd = 0;
      
      dns->rcode = 0;
      // 0 - NoError
      // 3 - NXDomain
      // 4 - NotImp
      
      dns->q_count = htons(1);
      dns->ans_count = htons(0);
      dns->auth_count = htons(0);
      dns->add_count = htons(0);
      
      qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
      ChangetoDnsNameFormat(qname , host);
      host[strlen(host)-1] = '\0';
      qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
      qinfo->qtype = htons( T_A );
      qinfo->qclass = htons(1);
      writer = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
      replysize = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);
      
      // assign unused IP
      
      FILE *fp = fopen("record.txt", "ab+");
      if (fp == NULL) {
         error("cannot open record file");
      }
      
      char savedHost[1024];
      char savedIp[30];
      char testIp[20];
      int needset = 1;
      while (fscanf(fp, "%s %s", savedHost, savedIp) == 2) {
         if (strcmp(host, savedHost) == 0) {
            *testIp = *savedIp;
            needset = 0;
            break;
         }
      }
      
      if (needset) {
         strcpy(testIp, "10.0.0.2");
         fprintf(fp, "%s %s\n", host, testIp);
      }
      
      fclose(fp);
      
      char *ip = testIp;
      dns->rcode = 0;
      dns->ans_count = htons(1);
      
      struct RES_RECORD *answer,*auth;
      struct in_addr *addr;
      addr = (struct in_addr*)malloc(sizeof(struct in_addr));
      lchar lc;
      
      answer = (struct RES_RECORD*)malloc(sizeof(struct RES_RECORD));
      strcpy(writer,qname);
      writer = writer + strlen((const char*)qname)+1;
      replysize += strlen((const char*)qname)+1;
      
      answer->resource = (struct R_DATA*)(writer);
      answer->resource->type = htons(1);
      answer->resource->data_len = htons(4);
      answer->resource->ttl = htonl(1800);
      answer->resource->_class = htons(1);
      writer = writer + sizeof(struct R_DATA);
      replysize += sizeof(struct R_DATA);
      
      inet_aton(ip,addr);
      lc.p = addr->s_addr;
      writer[0] = lc.a[0];
      writer[1] = lc.a[1];
      writer[2] = lc.a[2];
      writer[3] = lc.a[3];
      writer = writer + 4;
      replysize += 4;
      
      /*
       * sendto: echo the input back to the client
       */
//      n = sendto(sockfd, buf, strlen(buf), 0,
//                 (struct sockaddr *) &clientaddr, clientlen);
//      if (n < 0) 
//         error("ERROR in sendto");
      n = sendto(sockfd, (char*)buf, replysize, 0,
                 (struct sockaddr *) &clientaddr, clientlen);
      if (n < 0)
         error("ERROR in sendto");
      free(host);
      free(addr);
      free(answer);
      
   }
}






