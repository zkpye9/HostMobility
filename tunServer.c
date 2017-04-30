/*
Kunpeng Zhang (kunpengzhang@email.arizona.edu)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#define MAX_PENDING 32

int tun_alloc(char *dev, int flags)
{
   struct ifreq ifr;
   int fd, err;
   char *clonedev = "/dev/net/tun";
   
   /* Arguments taken by the function:
    *
    * char *dev: the name of an interface (or '\0'). MUST have enough
    *   space to hold the interface name if '\0' is passed
    * int flags: interface flags (eg, IFF_TUN etc.)
    */
   
   /* open the clone device */
   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
      return fd;
   }
   
   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));
   
   ifr.ifr_flags = flags;
   
   /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
    *        IFF_TAP   - TAP device
    *
    *        IFF_NO_PI - Do not provide packet information
    *
    *	If flag IFF_NO_PI is not set each frame format is:
    * 	     Flags [2 bytes]
    *	     Proto [2 bytes]
    *	     Raw protocol(IP, IPv6, etc) frame.
    */
   
   
   if (*dev) {
      /* if a device name was specified, put it in the structure; otherwise,
       * the kernel will try to allocate the "next" device of the
       * specified type */
      strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }
   
   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
      close(fd);
      return err;
   }
   
   /* if the operation was successful, write back the name of the
    * interface to the variable "dev", so the caller can know
    * it. Note that the caller MUST reserve space in *dev (see calling
    * code below) */
   strcpy(dev, ifr.ifr_name);
   
   return fd;
}

void die(char *msg)
{
   perror(msg);
   exit(1);
}

struct pseudo_header
{
   u_int32_t source_address;
   u_int32_t dest_address;
   u_int8_t placeholder;
   u_int8_t protocol;
   u_int16_t tcp_length;
};

unsigned short tcpSum(unsigned short *buffer, int size)
{
   unsigned long cksum=0;
   while(size >1)
   {
      cksum+=*buffer++;
      size -=sizeof(unsigned short);
   }
   if(size)
      cksum += *(unsigned char*)buffer;
   
   cksum = (cksum >> 16) + (cksum & 0xffff);
   cksum += (cksum >>16);
   return (unsigned short)(~cksum);
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
   register long sum;
   unsigned short oddbyte;
   register short answer;
   
   sum=0;
   while(nbytes>1) {
      sum+=*ptr++;
      nbytes-=2;
   }
   if(nbytes==1) {
      oddbyte=0;
      *((u_char*)&oddbyte)=*(u_char*)ptr;
      sum+=oddbyte;
   }
   
   sum = (sum>>16)+(sum & 0xffff);
   sum = sum + (sum>>16);
   answer=(short)~sum;
   
   return(answer);
}


/* Usage: tapReader [tap device name]*/
int main (int argc, char * argv[])
{
   char tun_name[IFNAMSIZ];
   const int FRAMESIZE = 65536;
   char buffer[FRAMESIZE];
   
   int nread, maxfd, retn;
   int sock_fd, tap_fd;
   struct sockaddr_in localSA, remoteSA;
   fd_set rset;
   struct ethhdr * p_ether;
   int ethertype;
   struct iphdr *p_ip;
   
   char usage[] = "usage: tapudp dev local_addr local_port remote_addr remote_port";
   if(argc != 6) {
      printf("%s\n", usage);
      exit(1);
   }
   
   strcpy(tun_name, argv[1]);
   
   memset((char *) &localSA, 0, sizeof(localSA));
   localSA.sin_family = AF_INET;
   if(inet_aton(argv[2], &(localSA.sin_addr)) == 0)
      die("invalid local address");
   localSA.sin_port = htons(atoi(argv[3]));
   socklen_t addrlen = sizeof(localSA);
   
   
   memset((char *) &remoteSA, 0, sizeof(remoteSA));
   remoteSA.sin_family = AF_INET;
   if(inet_aton(argv[4], &(remoteSA.sin_addr)) == 0)
      die("invalid remote address");
   remoteSA.sin_port = htons(atoi(argv[5]));
   
   
   /* Build the connection between program and tap device*/
   int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
   if(tun_fd < 0) die("Allocating interface");
   
   if(ioctl(tun_fd, TUNSETNOCSUM, 1) < 0)
      die("ioctl TUNSETNOCSUM error");
   
   
   /* create a UDP socket and connect to a remote IP:port */
   sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if(sock_fd < 0) die("creating socket");
   
   if (bind(sock_fd, (struct sockaddr *) &localSA, sizeof(localSA)) != 0)
      die("bind()");
   
   
   if(connect(sock_fd, (struct sockaddr *) &remoteSA, sizeof(remoteSA)) != 0)
      die("connect()");
   
   
   struct iphdr *newIpDes = NULL;
   struct iphdr *newIpSrc = NULL;
   struct tcphdr *tcpBuffer = NULL;
   struct pseudo_header psh;
   char ipBuffer[32];
   char *pseudogram;
   char *data;
   
   
   /* Infinite loop, read from tap device */
   while (1) {
      FD_ZERO(&rset);
      FD_SET(sock_fd, &rset);
      FD_SET(tun_fd, &rset);

      // originally outside the loop
      maxfd = sock_fd > tun_fd ? sock_fd : tun_fd;
      maxfd++;
      
      retn = select(maxfd, &rset, NULL, NULL, NULL);
      if(retn == -1) perror("select()");
      else if(retn == 0) perror("select timeout");
      else { // retn > 0
         if(FD_ISSET(tun_fd, &rset)) {
            nread = read(tun_fd,buffer,sizeof(buffer));
            printf("Read %d bytes from device %s\n", nread, tun_name);
            if(nread > 0) { 
               newIpDes = (struct iphdr*)&buffer;
               strcpy(ipBuffer, "192.168.6.3");
               newIpDes->daddr =inet_addr ( ipBuffer );
               if(write(sock_fd, buffer, nread) != nread)
                  perror("error in writing to UDP\n");
               else {
                  printf("already send\n");
               }
               memset(buffer,'\0', FRAMESIZE);
            } else
               perror("error in reading from tap");
         }
         if(FD_ISSET(sock_fd, &rset)) {
            nread = read(sock_fd,buffer,sizeof(buffer));
            printf("read succeed: %d\n", nread);
              
            data = buffer +sizeof(struct iphdr) + sizeof(struct tcphdr);
            newIpSrc = (struct iphdr*)&buffer;
            strcpy(ipBuffer, "127.1.0.2");
            newIpSrc->saddr =inet_addr( ipBuffer);
            newIpSrc->check = 0;
            
            newIpSrc->check = csum ((unsigned short *) newIpSrc, ((int)(newIpSrc->ihl))*4);
            
            tcpBuffer = (struct tcphdr*)(buffer+sizeof(struct iphdr));
            tcpBuffer->check = 0;
         
            
            psh.source_address = newIpSrc->saddr;
            psh.dest_address = newIpSrc->daddr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;      /////
            psh.tcp_length = htons(nread - (newIpSrc->ihl)*4 );
            printf("space2 before: %d\n", nread - (newIpSrc->ihl)*4  );
            
            int psize = sizeof(struct pseudo_header) + nread-(newIpSrc->ihl)*4 ;
            printf("space: %d\n", psize);
            pseudogram = malloc(psize);
            
            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header) , tcpBuffer , nread-(newIpSrc->ihl)*4);
            
            printf("space2: %d\n", ntohl(psh.tcp_length));
            printf("source Port and Destination Port: %d   %d\n", ntohs(tcpBuffer->source), ntohs(tcpBuffer->dest));
            
            tcpBuffer->check = tcpSum( (unsigned short*) pseudogram , psize);
            printf ("tcp source %d\n",tcpBuffer->source);
            printf("length: %d\n", psh.tcp_length);
            printf("data length: %d\n", strlen(data));
            
            if(write(tun_fd, buffer, nread) != nread)
               perror("error in writing to tap");
            else {
               printf("write to tap\n");
            }

            memset(buffer,'\0', FRAMESIZE);
            free(pseudogram);
         }
      }
      
   }
   
}







