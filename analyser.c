#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define FILENAME 50
#define line_length 16
#define gap 8

//idea :void pointer in packet, will always point to lower type of protocol - so packet -> ethernet II -> tcp -> http for example

typedef struct packet{
    int number;
    u_char *pkt_data;
    short visited;
    short type;                         //1 - Ethernet II, 2 - IEE 802.3 RAW/SNAP/LLC? waduhek
    char source_address[12];
    char destination_address[12];
    char protocol[10];
    int len;
}PACKET;

typedef struct ethernet{                //extension for ethernet II packets
    PACKET *packet;                     //extension points to core packet
    char source_IP[16];
    char destination_IP[16];
    char protocol[10];
    int destination_port;
    int source_port;
}ETHERNET;

void help(){
    printf("Network communication analyser by Juraj Bedej (C)\n");
    printf("Assignment for PKS subject\n");
    printf("<:help> to show help menu\n");
    printf("<:exit> to quit the interactive console\n");
    printf("<filename> to analyse .pcap file\n");
    printf("Use the following switches in combination with .pcap file path:\n");
    printf("\t <-HTTP> to filter all HTTP packets\n");
    printf("\t <-HTTPS> to filter all HTTPS packets\n");
    printf("\t <-TELNET> to filter all TELNET packets\n");
    printf("\t <-SSH> to filter all SSH packets\n");
    printf("\t <-FTPc> to filter all FTP Control packets\n");
    printf("\t <-FTPd> to filter all FTP Data packets\n");
    printf("\t <-TFTP> to filter all TFTP packets\n");
    printf("\t <-ICMP> to filter all ICMP Data packets\n");
    printf("\t <-ARP> to filter all ARP Data packets\n");
    printf("Using no switch will result in printing of all packets\n");
    printf("\nExample of usage: <filename> <-switch> <-switch>\n");
}

pcap_t *openPcap(char *file){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(file, errbuf);
    if(p == NULL){
        printf("Error: 'Invalid .pcap file entered'\n");
        return NULL;
    }
    return p;
}

int header_len(int len){                                                       //funkcia vracia pocet bajtov prenesenych po mediu
    if(len <= 60)
        return 64;
    else
        return len + 4;
}

char *stringifyType(PACKET packet){
    if(packet.type == 1)
        return "Ethernet II";
    else if(packet.type == 2)
        return "IEE 802.3 LLC + SNAP";
    else if(packet.type == 3)
        return "IEE 802.3 RAW";
    else
        return "IEE 802.3 LLC";
}

void printAddress(FILE *f, char *address){
    int i = 0;
    for(i = 0; i < 12; i++){
        if(i % 2 == 0 && i != 0){
            fprintf(f, " ");
        }
        fprintf(f,"%X", address[i]);
    }
    fprintf(f, "\n");
}

void printAnalysis(FILE *f, PACKET packet){
    int i;
    fprintf(f, "rámec %d\n", packet.number);
    fprintf(f, "dĺžka rámca poskytnutá pcap API - %d B\n", packet.len);
    fprintf(f, "dĺžka rámca prenášaného po médiu - %d B\n", header_len(packet.len));
    fprintf(f, "%s\n", stringifyType(packet));
    fprintf(f, "Zdrojová MAC adresa: ");
    printAddress(f, packet.source_address);
    fprintf(f, "Cieľová MAC adresa: ");
    printAddress(f, packet.destination_address);
    for(i = 0; i < packet.len; i++){
        if(i % line_length == 0 && i != 0)
            fprintf(f,"\n");
        else if(i % gap == 0 && i != 0)
            fprintf(f,"  ");
        fprintf(f,"%02X ",packet.pkt_data[i]);
    }
    fprintf(f, "\n\n");
}

PACKET *init(pcap_t *f, PACKET *packets, int *count){
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int i = 0, j;
    printf("Analysing .pcap file... ");
    while(pcap_next_ex(f,&pkt_header,&pkt_data) > 0){
        packets = realloc(packets, (i + 1) * sizeof(PACKET));
        packets[i].pkt_data = malloc(pkt_header -> caplen * sizeof(u_char));
        packets[i].number = i + 1;
        packets[i].visited = 0;
        packets[i].len = pkt_header->len;
        for(j = 0; j < pkt_header -> caplen; j++) {
            packets[i].pkt_data[j] = pkt_data[j];
        }
        i++;
    }
    printf(".pcap file contains %d packets\n", i - 1);
    *count = i - 1;
    return packets;
}

ETHERNET *initEthernet(PACKET *packets, ETHERNET *ethernet, int count){
    int i, j = 0;
    for(i = 0; i < count; i++){
        if(packets[i].type == 1){
            ethernet = realloc(ethernet, (j + 1) * sizeof(ETHERNET));
            ethernet[j].packet = &packets[i];
            j++;
        }
    }
    printf(".pcap file contains %d Ethernet II packets\n", j);
    return ethernet;
}

PACKET *setType(PACKET *packets, int count){
    int i;
    for(i = 0; i < count; i++){
        if(packets[i].pkt_data[12] > 5 || (packets[i].pkt_data[12] == 5 && packets[i].pkt_data[13] > 208))
            packets[i].type = 1;        //Ethernet II
        else if(packets[i].pkt_data[14] == 170 && packets[i].pkt_data[15] == 170)
            packets[i].type = 2;        //IEE 802.3 LLC + SNAP
        else if(packets[i].pkt_data[14] == 255 && packets[i].pkt_data[15] == 255)
            packets[i].type = 3;        //IEE 802.3 RAW
        else
            packets[i].type = 4;        //IEE 802.3 LLC
    }
    return packets;
}

PACKET *setAddress(PACKET *packets, int count){
    int i, j;
    for(i = 0; i < count; i++){
        for(j = 0; j < packets[i].len; j++){
            if(j < 6){
                packets[i].destination_address[j * 2] = packets[i].pkt_data[j]/16;
                packets[i].destination_address[j * 2 + 1] = packets[i].pkt_data[j]%16;
            }
            if(j >= 6 && j < 12){
                packets[i].source_address[(j - 6) * 2] = packets[i].pkt_data[j]/16;
                packets[i].source_address[(j - 6) * 2 + 1] = packets[i].pkt_data[j]%16;
            }
        }
    }
    return packets;
}

PACKET *setProtocol(PACKET *packets, int count){
    int i;
    for(i = 0; i < count; i++){

    }
    return packets;
}

void analysePcap(PACKET *packets, int count){
    FILE *o = fopen("output.txt", "w");
    packets = setAddress(packets, count);
    packets = setType(packets, count);
    ETHERNET *ethernet = malloc(sizeof(ETHERNET));
    ethernet = initEthernet(packets, ethernet, count);
    int i;
    for(i = 0; i < count; i++){
        printAnalysis(o, packets[i]);
    }
    printf("Analysis stored to: %s\n", _fullpath(NULL, "output.txt", FILENAME));
    fclose(o);
    free(ethernet);
}

void handleSwitches(char *filename){
    /*
    char temp[6];
    short ns = 1;
    while(scanf("%s", temp) > 0){
        ns = 0;
        printf("Used switch: %s\n", temp);
        memset(temp, 0, strlen(temp));
    }
    if(ns)
        printf("No switches used\n");
    */
    int count;
    pcap_t *f = openPcap(filename);
    PACKET *packets = malloc(sizeof(PACKET));
    packets = init(f, packets, &count);
    analysePcap(packets, count);
    free(packets);
}

int prompt(char *filename){
    memset(filename, 0, strlen(filename));
    printf("\n>>");
    fflush(stdin);
    scanf("%s", filename);
    if(strcmp(filename, ":exit") == 0) {
        printf("\nExiting..");
        return 0;
    }
    else if (strcmp(filename, ":help") == 0){
        help();
        return 1;
    }
    else if(openPcap(filename) != NULL){                                                //we begin analysing valid .pcap file, taking switches into consideration...
        handleSwitches(filename);
        return 1;
    }
    else{
        //else keep cycling
        return 1;
    }
}

int main(){
    char *filename = malloc(FILENAME);
    printf("Welcome to he interactive console: \n");
    while(prompt(filename));
    free(filename);
    return 0;
}