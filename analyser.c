#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define FILENAME 10

typedef struct packet{
    u_char *pkt_header;
}PACKET;

void openPcap(char *file){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(file, errbuf);
}

void help(){
    printf("Network communication analyser by Juraj Bedej (C)\n");
    printf("Assignment for PKS subject\n");
    printf("<:help> to show help menu\n");
    printf("<:exit> to quit the interactive console\n");
    printf("<filename> to analyse .pcap file\n");
    printf("Use the following switches in combination with .pcap file name:\n");
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
    else if(strstr(filename, ".pcap") != NULL){
        return 1;
    }
    else{
        printf("I can only analyse .pcap files!");
        return 1;
    }
}

int main(){
    char *filename = malloc(FILENAME);
    printf("Welcome to he interactive console: \n");
    while(prompt(filename)) {

    }
    return 0;
}