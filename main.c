#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

int menu();
pcap_t* loadFile(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet);
uint32_t showNumberOfPackets(pcap_t* pcap, long* pos, struct pcap_pkthdr* header, const uint8_t* packet);
void listPackages(pcap_t* pcap, uint32_t* nrOfPackets);
void view(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet);

int main()
{
    uint32_t choice = -1;
    pcap_t* pcap = NULL;
    long pos = -1;
    struct pcap_pkthdr* header = NULL;
    const uint8_t* packet = NULL;
    uint32_t nrOfPackets = 0;

    while (choice != 9)
    {
    system("clear");
    choice = menu();
    system("clear");
    switch(choice)
    {
        case 1:
        pcap = loadFile(pcap, &pos, &nrOfPackets, header, packet);
        break;

        case 2:
        nrOfPackets = showNumberOfPackets(pcap, &pos, header, packet);
        break;

        case 3:
        listPackages(pcap, &nrOfPackets);
        break;

        case 4:
        view(pcap, &pos, &nrOfPackets, header, packet);
        break;

        case 9:
        printf("Exiting program...\n");
        break;

        default:
        printf("Unknown command.");
        getchar();
        break;
    }   
    }
    if (pcap != NULL)
    {
    pcap_close(pcap);
    }
    return 0;
}


int menu()
{
    uint32_t choice = -1;
    printf("1. Read filename into memory.\n\n2. Show number of packets present.\n\n3. List range of packets.\n\n4. View packet.\n\n5. Edit packet.\n\n6. Insert/Add packet.\n\n7. Write to file.\n\n8. Help.\n\n9. Quit program.\n\n");
    printf("Please enter your choice: ");
    scanf("%i", &choice);
    getchar();
    return choice;
}

pcap_t* loadFile(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet)
{
    if (pcap == NULL)
    {
        uint32_t capacity = 30;
        char errorBuffer[PCAP_ERRBUF_SIZE];
        char fileName[capacity];
        printf("Enter filename: ");
        fgets(fileName, capacity, stdin);
        fileName[strlen(fileName) -1] = '\0';
        pcap = pcap_open_offline(fileName, errorBuffer);
        if (pcap != NULL)
        {
            printf("File '%s' opened successfully!", fileName);
            *pos = ftell(pcap_file(pcap));
            getchar();

            fseek(pcap_file(pcap), *pos, SEEK_SET);
            while (pcap_next_ex(pcap, &header, &packet) >= 0)
            {
                ++(*nrOfPackets);
            }
            return pcap;
        }
        else    
        {
            printf("\nERROR, file not loaded!");     
            getchar();
            return NULL;  
        }
    }
    else
    {
        fprintf(stderr,"File already loaded into memory.");
        getchar();
        return pcap;            
    } 
}

uint32_t showNumberOfPackets(pcap_t* pcap, long* pos, struct pcap_pkthdr* header, const uint8_t* packet)
{
    if (pcap != NULL)
        {
        uint32_t nrOfPackets = 0;

        fseek(pcap_file(pcap), *pos, SEEK_SET);
        while (pcap_next_ex(pcap, &header, &packet) >= 0)
        {
            ++nrOfPackets;
        }
        printf("Number of packets present in pcap-file: %i", nrOfPackets);
        getchar();
        return nrOfPackets;
        }
    else
    {
     fprintf(stderr, "Error; no file loaded");   
    }
}

void listPackages(pcap_t* pcap, uint32_t* nrOfPackets)
{
    if (pcap != NULL)
    {
    int startIndex = -1;
    int endIndex = -1;
    printf("Number of packets available in this file: %i\n", *nrOfPackets);
    printf("Please input the start-Id of the packet range to be listed, as a single digit: ");
    scanf("%d", &startIndex);
    getchar();
     printf("\nPlease input the end-Id of the packet range to be listed, as a single digit: ");
     scanf("%d", &endIndex);
     getchar();

     if (startIndex <= *nrOfPackets && startIndex > 0 && endIndex <= *nrOfPackets)
     {
         for (int i = startIndex; i <= endIndex; i++)
         {
             printf("PktId%d\n", i);
         }
         getchar();
     }
     else
     {
         {
             printf("Error: Your ID-selection is out of range.");
             getchar();
         }
     }
     
    }
}

void view(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet)
{
    if (pcap != NULL)
    {
        fseek(pcap_file(pcap), *pos, SEEK_SET);
        struct pcap_pkthdr header2;
        int i = 1;

        while (pcap_next_ex(pcap, &header, &packet) >= 0)
        {
            header2.caplen = header->caplen;
            header2.len = header->len;
            printf("Packet %d:\n", i);
            printf("Capture Length: %d", (int)header2.caplen);
            printf("\n");
            printf("Length: %d", header2.len);
            printf("\n");
            i++;

            u_char* charPtr = (u_char*)packet;

            printf("\n---Ethernet layer---\n\n");
            printf("Destination MAC Adress: ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3), *(charPtr+4), *(charPtr+5));
            charPtr += 6;
            printf("\nSource MAC Adress: ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3), *(charPtr+4), *(charPtr+5));
            charPtr += 6;
            unsigned short* shortPtr = (unsigned short*)charPtr;
            if (ntohs(*shortPtr) == 0x0800)
            {
                printf("\nEthertype: 0x0800 (IP)");
                printf("\n\n---IP Layer---\n");
                shortPtr += 1;
                charPtr = (u_char*)shortPtr;
                char ipVer = *charPtr >> 4;
                printf("\nIP-Version: %d", ipVer); 
                char headerLength = *charPtr << 4;
                headerLength = headerLength >> 4;
                printf("\nIP Header Length: %d", headerLength * 4); //Number of 32-bit words, so we multiply by 4 to get the bytes it surmount to. 
                charPtr += 1;
                printf("\nType-Of-Service (tos): %d", *charPtr);
                charPtr += 1;
                shortPtr = (unsigned short*)charPtr;
                printf("\nIP-Length: %d", ntohs(*shortPtr));
                shortPtr += 1;
                printf("\nID: 0x%04x", ntohs(*shortPtr));
                shortPtr += 1;
                charPtr = (u_char*)shortPtr;
                printf("\nFlag: 0x%02x%02x", *charPtr, *(charPtr+1));
                printf("\nFragment Offset: %02x", *(charPtr+1));
                charPtr += 2;
                printf("\nTime-to-live (ttl): %d", *charPtr); 
                charPtr += 1;
                if(*charPtr == 17) //UDP
                {
                    printf("\nIP-Protocol: %d (UDP)", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short*)charPtr;
                    printf("\nIP-Checksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    charPtr = (u_char*)shortPtr;
                    printf("\n\n---UDP Layer---\n");
                    printf("\nIP-source: %d.%d.%d.%d", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3));
                    charPtr += 4;
                    printf("\nIP-destination: %d.%d.%d.%d", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3));
                    charPtr += 4;
                    shortPtr = (unsigned short*)charPtr; 
                    printf("\nUDP Source Port: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nUDP Destination Port: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nLength: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nChecksum: 0x%x", ntohs(*shortPtr));
                }
                else if (*charPtr == 6) //TCP
                {
                    printf("\nIP-Protocol: %d (TCP)", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short*)charPtr;
                    printf("\nIP-Checksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    charPtr = (u_char*)shortPtr;
                    printf("\n\n---TCP Layer---\n");
                    printf("\nIP-source: %d.%d.%d.%d", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3));
                    charPtr += 4;
                    printf("\nIP-destination: %d.%d.%d.%d", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3));
                    charPtr += 4;
                    shortPtr = (unsigned short*)charPtr;
                    printf("\nTCP Source Port: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nTCP Destination Port: %d", ntohs(*shortPtr));
                    shortPtr += 1;             
                    unsigned int* intPtr = (unsigned int*)shortPtr;      
                    printf("\nSequence Number: 0x%08x", ntohl(*intPtr));
                    intPtr += 1;
                    printf("\nAcknowledgement Number: 0x%08x", ntohl(*intPtr));
                    intPtr += 1;
                    charPtr = (u_char*)intPtr;
                    char firstFourBits = *charPtr >> 4;
                    printf("\nOffset: %d", (firstFourBits * 4)); //Number of 32-bit words, so we multiply by 4 to get the bytes it surmount to. 
                    char lastFourBits = *charPtr << 4;
                    lastFourBits = lastFourBits >> 4;
                    printf("\nSize: %d", lastFourBits); //Should be 0.
                    charPtr += 1;
                    printf("\nFlag: 0x%03x", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short*)charPtr;
                    printf("\nWindow size: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nChecksum: 0x%04x", ntohs(*shortPtr));
                }
                else if (*charPtr == 1) // ICMP
                {
                    printf("\nIP-Protocol: %d (ICMP)", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short*)charPtr;
                    printf("\nIP-Checksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    charPtr = (u_char*)shortPtr;
                    printf("\n\n---ICMP Layer---\n");
                    printf("\nIP-source: %d.%d.%d.%d", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3));
                    charPtr += 4;
                    printf("\nIP-destination: %d.%d.%d.%d", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3));
                    charPtr += 4;


                }
                else
                {
                    printf("Transport layer not of type TCP, UDP, or ICMP - the following packet information will be disregarded.");   
                }
            }
            else
            {
                printf("\nPacket not of ethertype IPV4; the following packet infomation will be disregarded.");
            }
            printf("\n\n");
        }
        printf("Press enter key to continue.");
        getchar();
    }                
    else
    {
         fprintf(stderr, "Error; no file loaded");
         getchar();
    }
}
                        
                    
                
                    
            

            


    