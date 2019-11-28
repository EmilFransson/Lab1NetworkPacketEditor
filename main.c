#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

typedef struct 
    {
        struct pcap_pkthdr* header;
        uint8_t* packet;
    } Packets;
    Packets* packets = NULL;

int menu();
pcap_t* loadFile(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet);
uint32_t showNumberOfPackets(pcap_t* pcap, long* pos, struct pcap_pkthdr* header, const uint8_t* packet);
void listPackages(pcap_t* pcap, uint32_t* nrOfPackets);
void view(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet);
void edit(uint32_t* nrOfPackets);

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

        case 5:
        edit(&nrOfPackets);
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
        for (int i = 0; i < nrOfPackets; i++)
        {
            free(packets[i].header);
            free(packets[i].packet);    
        }
        free(packets);
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

        packets = calloc(0, sizeof(struct pcap_pkthdr*) + sizeof(uint8_t*));
        if (pcap != NULL)
        {
            printf("File '%s' opened successfully!", fileName);
            getchar();
            *pos = ftell(pcap_file(pcap));

            fseek(pcap_file(pcap), *pos, SEEK_SET);
            while (pcap_next_ex(pcap, &header, &packet) >= 0)
            {
                ++(*nrOfPackets);
                packets = realloc(packets, *nrOfPackets * sizeof(Packets));
                packets[*nrOfPackets - 1].header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr*));
                packets[*nrOfPackets - 1].header->caplen = header->caplen;
                packets[*nrOfPackets - 1].header->len = header->len;
                packets[*nrOfPackets - 1].header->ts = header->ts;
                
                packets[*nrOfPackets - 1].packet = (uint8_t*)malloc(header->len);
                for (int i = 0; i < (int)header->len; i++)
                {
                    packets[*nrOfPackets - 1].packet[i] = packet[i];
                }
            }
            return pcap;
        }
        else    
        {
            printf("\nERROR, file not loaded!");  
            printf("\n%s", errorBuffer);   
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
     fprintf(stderr, "Error; no file loaded into memory.");
     getchar();   
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

     if (startIndex <= *nrOfPackets && startIndex > 0 && endIndex <= *nrOfPackets && endIndex >= startIndex)
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
    else
    {
        fprintf(stderr, "Error; no file loaded into memory.");
        getchar();
    }
}

void view(pcap_t* pcap, long* pos, uint32_t* nrOfPackets, struct pcap_pkthdr* header, const uint8_t* packet)
{
    if (pcap != NULL)
    {
        for (int i = 0; i < *nrOfPackets; i++)
        {
            printf("Packet %d:", i + 1);
            printf("\nCapture Length: %d", (int)packets[i].header->caplen);
            printf("\nLength: %d", packets[i].header->len);
            printf("\nCapture time: %f micro-seconds", (float)packets[i].header->ts.tv_usec);

            u_char* charPtr = (u_char*)packets[i].packet;

            printf("\n\n---Ethernet layer---\n\n");
            printf("Destination MAC Adress: %02x:%02x:%02x:%02x:%02x:%02x", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3), *(charPtr+4), *(charPtr+5));
            charPtr += 6;
            printf("\nSource MAC Adress: %02x:%02x:%02x:%02x:%02x:%02x", *charPtr, *(charPtr+1), *(charPtr+2), *(charPtr+3), *(charPtr+4), *(charPtr+5));
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
                printf("\nType-Of-Service (tos / DSCP|ECN): 0x%02x, (%d)", *charPtr, *charPtr);
                charPtr += 1;
                shortPtr = (unsigned short*)charPtr;
                printf("\nIP-Length: %d", ntohs(*shortPtr));
                shortPtr += 1;
                printf("\nID: 0x%04x, (%d)", ntohs(*shortPtr), ntohs(*shortPtr));
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
                    printf("\nType: %d", *charPtr);
                    charPtr += 1;
                    printf("\nCode: %d", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short*)charPtr;
                    printf("\nChecksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nID: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nSequence Number: 0x%04x", ntohs(*shortPtr));
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
         fprintf(stderr, "Error; no file loaded into memory.");
         getchar();
    }
}

void edit(uint32_t* nrOfPackets)
{
    if (*nrOfPackets > 0)
    {
        uint32_t packetChoice = -1;
        printf("There are %d number of packets loaded into memory", *nrOfPackets);
        printf("\nPlease input the number of the packet you would like to edit: ");
        scanf("%d", &packetChoice);
        getchar();
        packetChoice--;
        if (packetChoice >= 0 && packetChoice < *nrOfPackets)
        {
            printf("Capture length: ");
            scanf("%d", &packets[packetChoice].header->caplen);
            getchar();
            printf("Total Length: ");
            scanf("%d", &packets[packetChoice].header->len);
            getchar();
            printf("Capture time (in micro seconds): ");
            scanf("%ld", &packets[packetChoice].header->ts.tv_usec);
            getchar();
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            char macDest[18];
            bool correctMAC = false;
            while (strlen(macDest) != 17 || correctMAC == false)
            {
                printf("Destination MAC Adress (WITH colons and in the form (XX:XX:XX:XX:XX:XX)): ");
                fgets(macDest, 18, stdin);
                getchar();
                for (int i = 0; i < 18; i++)
                {
                    if (macDest[i] == '\n')
                    {
                        macDest[i] = '\0';
                    }
                }
                if (strlen(macDest) != 17)
                {
                    printf("Incorrect length, try again.\n");
                    getchar();
                }
                else
                {
                    correctMAC = true;
                    for (int i = 0; i < 5 && correctMAC == true; i++)
                    {
                        if (macDest[(i * 3) + 2] != ':')
                        {
                            correctMAC = false;
                        }
                    }
                    for (int i = 0; i < 6 && correctMAC == true; i++)
                    {
                        if (macDest[i * 3] > 102 || (macDest[i * 3] > 0 && macDest[i * 3] < 48) 
                        || (macDest[i * 3] > 70 && macDest[i * 3] < 97) || (macDest[i * 3] > 57 && macDest[i * 3] < 65))
                        {
                            correctMAC = false;
                        }
                        else if (macDest[(i * 3) + 1] > 102 || (macDest[(i * 3) + 1] > 0 && macDest[(i * 3) + 1] < 48) 
                        || (macDest[(i * 3) + 1] > 70 && macDest[(i * 3) + 1] < 97) || (macDest[(i * 3) + 1] > 57 && macDest[(i * 3) + 1] < 65))
                        {
                            correctMAC = false;
                        }
                    }
                    if (correctMAC == false)
                    {
                        printf("Incorrect input, please try again.\n");
                    }
                }
           }
            int macD[6];
            sscanf(macDest, "%x:%x:%x:%x:%x:%x", &macD[0], &macD[1], &macD[2], &macD[3], &macD[4], &macD[5]);
            char finalMacDest[6];
            for (int i = 0; i < 6; i++)
            {
                finalMacDest[i] = macD[i];
            }
            u_char* charPtr = (u_char*)packets[packetChoice].packet;
            for (int i = 0; i < 6; i++)
            {
                *(charPtr + i) = finalMacDest[i];
            }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            charPtr += 6;
            char macSource[18];
            correctMAC = false;
            while (strlen(macSource) != 17 || correctMAC == false)
            {
                printf("Source MAC Adress (WITH colons and in the form (XX:XX:XX:XX:XX:XX)): ");
                fgets(macSource, 18, stdin);
                getchar();
                for (int i = 0; i < 18; i++)
                {
                    if (macSource[i] == '\n')
                    {
                        macSource[i] = '\0';
                    }
                }
                if (strlen(macSource) != 17)
                {
                    printf("Incorrect length, try again.\n");
                    getchar();
                }
                else
                {
                    correctMAC = true;
                    for (int i = 0; i < 5 && correctMAC == true; i++)
                    {
                        if (macSource[(i * 3) + 2] != ':')
                        {
                            correctMAC = false;
                        }
                    }
                    for (int i = 0; i < 6 && correctMAC == true; i++)
                    {
                        if (macSource[i * 3] > 102 || (macSource[i * 3] > 0 && macSource[i * 3] < 48) 
                        || (macSource[i * 3] > 70 && macSource[i * 3] < 97) || (macSource[i * 3] > 57 && macSource[i * 3] < 65))
                        {
                            correctMAC = false;
                        }
                        else if (macSource[(i * 3) + 1] > 102 || (macSource[(i * 3) + 1] > 0 && macSource[(i * 3) + 1] < 48) 
                        || (macSource[(i * 3) + 1] > 70 && macSource[(i * 3) + 1] < 97) || (macSource[(i * 3) + 1] > 57 && macSource[(i * 3) + 1] < 65))
                        {
                            correctMAC = false;
                        }
                    }
                    if (correctMAC == false)
                    {
                        printf("Incorrect input, please try again.\n");
                    }
                }
           }
            int macS[6];
            sscanf(macSource, "%x:%x:%x:%x:%x:%x", &macS[0], &macS[1], &macS[2], &macS[3], &macS[4], &macS[5]);
            char finalMacSource[6];
            for (int i = 0; i < 6; i++)
            {
                finalMacSource[i] = macS[i];
            }
            for (int i = 0; i < 6; i++)
            {
                *(charPtr + i) = finalMacSource[i];
            }
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            printf("Ethertype version set to 0x0800 - the only allowed.");
            charPtr += 6;
            char ipType[] = "08:00";
            int ipT[2];
            sscanf(ipType, "%x:%x", &ipT[0], &ipT[1]);
            char finalIpType[2];
            finalIpType[0] = ipT[0];
            finalIpType[1] = ipT[1];
            *charPtr = finalIpType[0];
            *(charPtr + 1) = finalIpType[1];
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            printf("\n---IP-Layer---");
            printf("\nIP-version set to 4 - the only allowed.");
            int ihl = -1;
            bool correctIHL = false;
            while (correctIHL == false)
            {
                printf("\nIHL (5 (no options) or 6 (with options)): ");
                scanf("%d", &ihl);
                getchar();
                if (ihl == 5 || ihl == 6)
                {
                    correctIHL = true;
                }
                else
                {
                    printf("Incorrect input, please try again.\n");
                }
            }
            char ipVer[2];
            if (ihl == 5)
            {
                ipVer[0] = '4';
                ipVer[1] = '5';

            }
            else
            {
                ipVer[0] = '4';
                ipVer[1] = '6';
            }
            int ipV;
            sscanf(ipVer, "%x", &ipV);
            printf("%x", ipV);
            getchar();
            char finalIpVer = ipV;
            charPtr += 2;
            *charPtr = finalIpVer;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////             
            charPtr += 1;
            int dscp = -1;
            bool correctDSCP = false;
            while (correctDSCP == false)
            {
                printf("DSCP (0 - 63): ");
                scanf("%d", &dscp);
                getchar();
                if (dscp < 0 || dscp > 63)
                {
                    printf("Incorrect input, please try again.\n");
                }
                else
                {
                    correctDSCP = true;
                }
            }
            int ECN = -1;
            bool correctECN = false;
            while(correctECN == false)
            {
                printf("ECN (0 - 3): ");
                scanf("%d", &ECN);
                if (ECN < 0 || ECN > 3)
                {
                    printf("Incorrect input, please try again.\n");
                }
                else
                {
                    correctECN = true;
                }
            }
            dscp = dscp << 2;
            int finalDSF = dscp | ECN;
            unsigned char finalDsfAsChar = finalDSF;
            *charPtr = finalDsfAsChar;
//////////////////////////////////////////////////////////////////////////////////////
            charPtr += 1;
            unsigned short totalLength = -1;
            bool correctTotalLength = false;
            while (correctTotalLength == false)
            {
                printf("Total Length (%d - 65535): ", (ihl * 4));
                scanf("%hd", &totalLength);
                if (totalLength >= (ihl * 4) && totalLength <= 65535)
                {
                    correctTotalLength = true;
                }
                else
                {
                    printf("Incorrect input, please try again.\n");
                }
            }
            unsigned short* shortPtr = (unsigned short*)charPtr;
            *shortPtr = htons(totalLength);
//////////////////////////////////////////////////////////////////////////////////////
            shortPtr += 1;
            unsigned short ID = -1;
            bool correctId = false;
            getchar();
            while (correctId == false)
            {
                bool isANumber = true;
                char check [6];
                printf("ID (0 - 65535): ");
                fgets(check, 6, stdin);
                for (int i = 0; i < 5; i++)
                {
                    if (check[i] == '\n')
                    {
                        check[i] = '\0';
                    }
                }
                for (int i = 0; i < strlen(check) && isANumber == true; i++)
                {
                    if (!(isdigit(check[i])))
                    {
                        isANumber = false;
                    }
                }
                if (isANumber == true)
                {
                    ID = atoi(check);
                    if (ID >= 0 && ID <= 65535)
                    {
                        correctId = true;
                    }
                }
                if (!correctId || !isANumber)
                {
                    printf("Incorrect input, please try again.");
                }
            }
            *shortPtr = htons(ID);
///////////////////////////////////////////////////////////////////////////////////////
            shortPtr += 1;
            printf("Flag set to 0x4000 - Dont fragment.");
            unsigned short flag = 0b0100000000000000;
            *shortPtr = htons(flag);
/////////////////////////////////////////////////////////////////////////////////////////
            shortPtr += 1;

            unsigned short ttl = -1;
            bool correctTtl = false;
            getchar();
            while (correctTtl == false)
            {
                bool isANumber = true;
                char check [4];
                printf("Time-to-live (1 - 255): ");
                fgets(check, 6, stdin);
                for (int i = 0; i < 4; i++)
                {
                    if (check[i] == '\n')
                    {
                        check[i] = '\0';
                    }
                }
                for (int i = 0; i < strlen(check) && isANumber == true; i++)
                {
                    if (!(isdigit(check[i])))
                    {
                        isANumber = false;
                    }
                }
                if (isANumber == true)
                {
                    ttl = atoi(check);
                    printf("TTL: %d", ttl);
                    getchar();
                    if (ttl >= 1 && ttl <= 65535)
                    {
                        correctTtl = true;
                    }
                }
                if (!correctId || !isANumber)
                {
                    printf("Incorrect input, please try again.\n");
                }
            }
            charPtr = (u_char*)shortPtr;
            *charPtr = ttl;     
///////////////////////////////////////////////////////////////////////////////////
            charPtr += 2;
            shortPtr = (unsigned short*)charPtr;
            printf("Header checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));
///////////////////////////////////////////////////////////////////////////////////            
            shortPtr += 1;
            

        }
                    
                    


        else
        {
            fprintf(stderr, "Error; input out of bounds.");
            getchar();
        }
    }
    else
    {
        fprintf(stderr, "Error; no file loaded into memory.");
        getchar();
    }
}