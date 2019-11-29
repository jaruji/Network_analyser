#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define FILENAME 50
#define line_length 16
#define gap 8

typedef struct packet{
    short number;
    u_char *pkt_data;
    short visited;
    int len;
}PACKET;

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

void printAnalysis(FILE *f, PACKET packet){
    int i;
    fprintf(f, "rámec %d\n", packet.number);
    fprintf(f, "dĺžka rámca poskytnutá pcap API - %d B\n", packet.len);
    fprintf(f, "dĺžka rámca prenášaného po médiu - %d B\n", header_len(packet.len));
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
    printf("Analysing .pcap file...");
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

void analysePcap(PACKET *packets, int count){
    FILE *o = fopen("output.txt", "w");
    int i;
    for(i = 0; i < count; i++){
        printAnalysis(o, packets[i]);
    }
    printf("Analysis stored to: %s\n", _fullpath(NULL, "output.txt", FILENAME));
    fclose(o);
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
}

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