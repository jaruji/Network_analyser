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
    int len;
}PACKET;

typedef struct uniqueIP{
    char *ip;
    int packetsSent;
}UNIQUE_IP;

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

char *getType(PACKET packet){
    if(packet.pkt_data[12] > 5 || (packet.pkt_data[12] == 5 && packet.pkt_data[13] > 208))
        return "Ethernet II";        //Ethernet II
    else if(packet.pkt_data[14] == 170 && packet.pkt_data[15] == 170)
        return "IEE 802.3 LLC + SNAP";        //IEE 802.3 LLC + SNAP
    else if(packet.pkt_data[14] == 255 && packet.pkt_data[15] == 255)
        return "IEE 802.3 RAW";        //IEE 802.3 RAW
    else
        return "IEE 802.3 LLC";        //IEE 802.3 LLC
}

char *getAddress(PACKET packet, int start){
    int i = 0, j;
    char *address = malloc(12 * sizeof(char));
    for(j = start; j < start + 6; j++) {
        address[i * 2] = packet.pkt_data[j] / 16;
        address[i * 2 + 1] = packet.pkt_data[j] % 16;
        i++;
    }
    return address;
}

char* getProtocol(PACKET packet){
    if(packet.pkt_data[12] == 8 && packet.pkt_data[13] == 0)
        return "IPv4";
    else if(packet.pkt_data[12] == 8 && packet.pkt_data[13] == 6)
        return "ARP";
    else if(packet.pkt_data[12] == 134 && packet.pkt_data[13] == 221)
        return "IPv6";
    else if(packet.pkt_data[12] == 128 && packet.pkt_data[13] == 155)
        return "Appletalk";
    return "";
}

char* getEthernetProtocol(PACKET packet){
    if(packet.pkt_data[23] == 6){
        return "TCP";
    }
    else if(packet.pkt_data[23] == 17){
        return "UDP";
    }
    else if(packet.pkt_data[23] == 1){
        return "ICMP";
    }
    else if (packet.pkt_data[23] == 2)
        return "IGMP";
    else
        return "";
}

int getPort(int a, int b){
    int tmp[4];
    tmp[0] = a / 16;
    tmp[1] = a % 16;
    tmp[2] = b / 16;
    tmp[3] = b % 16;
    return tmp[0]*16*16*16 + tmp[1] *16*16 + tmp[2]*16 + tmp[3];
}

char *getIP(PACKET packet, int start){
    int i; //26 - 30, 30-34
    char *ip = malloc(12 * sizeof(char));
    memset(ip, 0, 12);
    char *temp = malloc(3 * sizeof(char));
    for(i = start; i < start + 4; i++){
        memset(temp, 0, 4);
        sprintf(temp, "%d", packet.pkt_data[i]);
        strcat(ip, temp);
        if(i != start + 3)
            strcat(ip, ".");
    }
    free(temp);
    return ip;
}

int insertIP(UNIQUE_IP *uniqueIp, char *ip, int count, int last){
    int i;
    for(i = 0; i < count; i++){
        if(strcmp(ip, uniqueIp[i].ip) == 0) {
            uniqueIp[i].packetsSent++;
            return last;
        }
    }
    strcpy(uniqueIp[last].ip, ip);
    uniqueIp[last].packetsSent = 1;
    last++;
    return last;
}

int getMax(UNIQUE_IP *ip, int size){
    int max = 0, maxI, i;
    for(i = 0; i < size; i++){
        if(ip[i].packetsSent > max) {
            maxI = i;
            max = ip[i].packetsSent;
        }
    }
    return maxI;
}

void printAnalysis(FILE *f, PACKET* packets, int count){
    int i, j;
    UNIQUE_IP *uniqueIp = malloc(count * sizeof(UNIQUE_IP));
    for(i = 0; i < count; i++){
        uniqueIp[i].packetsSent = 0;
        uniqueIp[i].ip = malloc(12 * sizeof(char));
    }
    int last = 0;
    for(j = 0; j < count; j++) {
        fprintf(f, "rámec %d\n", packets[j].number);
        fprintf(f, "dĺžka rámca poskytnutá pcap API - %d B\n", packets[j].len);
        fprintf(f, "dĺžka rámca prenášaného po médiu - %d B\n", header_len(packets[j].len));
        fprintf(f, "%s\n", getType(packets[j]));
        fprintf(f, "Zdrojová MAC adresa: ");
        printAddress(f, getAddress(packets[j], 6));
        fprintf(f, "Cieľová MAC adresa: ");
        printAddress(f, getAddress(packets[j], 0));
        if(strcmp(getType(packets[j]), "Ethernet II") == 0) {
            fprintf(f, "%s\n", getProtocol(packets[j]));
            if(strcmp(getProtocol(packets[j]), "IPv4") == 0){
                fprintf(f, "zdrojová IP adresa: %s\n", getIP(packets[j], 26));
                last = insertIP(uniqueIp, getIP(packets[j], 26), count, last);
                fprintf(f, "cieľová IP adresa: %s\n", getIP(packets[j], 30));
                fprintf(f, "%s\n", getEthernetProtocol(packets[j]));
            }
        }
        for (i = 0; i < packets[j].len; i++) {
            if (i % line_length == 0 && i != 0)
                fprintf(f, "\n");
            else if (i % gap == 0 && i != 0)
                fprintf(f, "  ");
            fprintf(f, "%02X ", packets[j].pkt_data[i]);
        }
        fprintf(f, "\n\n");
    }
    fprintf(f, "IP adresy vysielajúcich uzlov: \n");
    for(i = 0; i < last; i++){
        fprintf(f,"%s\n", uniqueIp[i].ip);
    }
    fprintf(f, "Adresa uzla s najväčším počtom odoslaných paketov:\n");
    int index = getMax(uniqueIp, last);
    fprintf(f, "%s    %d paketov", uniqueIp[index].ip, uniqueIp[index].packetsSent);
    free(uniqueIp);
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
    printf(".pcap file contains %d packets\n", i);
    *count = i;
    return packets;
}

void analysePcap(PACKET *packets, int count){
    FILE *o = fopen("output.txt", "w");
    //packets = setAddress(packets, count);
    //packets = setType(packets, count);
    //int i;
    //for(i = 0; i < count; i++){
    printAnalysis(o, packets, count);
    //}
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