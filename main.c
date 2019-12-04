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
    struct pcap_pkthdr *header;
    uint8_t *packet;
} Packets;
Packets *packets = NULL;

int menu();
pcap_t *loadFile(pcap_t *pcap, long *pos, uint32_t *nrOfPackets, struct pcap_pkthdr *header, const uint8_t *packet);
uint32_t showNumberOfPackets(pcap_t *pcap, long *pos, struct pcap_pkthdr *header, const uint8_t *packet);
void listPackages(pcap_t *pcap, uint32_t *nrOfPackets);
void view(pcap_t *pcap, long *pos, uint32_t *nrOfPackets, struct pcap_pkthdr *header, const uint8_t *packet);
void edit(uint32_t *nrOfPackets);
void addInsert(uint32_t *nrOfPackets);
short shortFunction(char *fieldToEdit, unsigned short *shortPtr, unsigned int lowerLimit, unsigned int upperLimit, bool convertToChar, bool onlyReturn);
int intFunction(char *fieldToEdit, unsigned int *shortPtr, unsigned long lowerLimit, unsigned long upperLimit, bool onlyReturn);
bool userWantsToEdit(char *fieldtoEdit);

int main()
{
    uint32_t choice = -1;
    pcap_t *pcap = NULL;
    long pos = -1;
    struct pcap_pkthdr *header = NULL;
    const uint8_t *packet = NULL;
    uint32_t nrOfPackets = 0;

    while (choice != 9)
    {
        system("clear");
        choice = menu();
        system("clear");
        switch (choice)
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

        case 6:
            addInsert(&nrOfPackets);
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
    printf("1. Read filename into memory.\n\n2. Show number of packets present.\n\n3. List range of packets.\n\n4. View packet.\n\n5. Edit packet.\n\n6. Add/Insert packet.\n\n7. Write to file.\n\n8. Help.\n\n9. Quit program.\n\n");
    printf("Please enter your choice: ");
    scanf("%i", &choice);
    getchar();
    return choice;
}

pcap_t *loadFile(pcap_t *pcap, long *pos, uint32_t *nrOfPackets, struct pcap_pkthdr *header, const uint8_t *packet)
{
    if (pcap == NULL)
    {
        uint32_t capacity = 30;
        char errorBuffer[PCAP_ERRBUF_SIZE];
        char fileName[capacity];
        printf("Enter filename: ");
        fgets(fileName, capacity, stdin);
        fileName[strlen(fileName) - 1] = '\0';
        pcap = pcap_open_offline(fileName, errorBuffer);

        packets = calloc(0, sizeof(struct pcap_pkthdr *) + sizeof(uint8_t *));
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
                packets[*nrOfPackets - 1].header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr *));
                packets[*nrOfPackets - 1].header->caplen = header->caplen;
                packets[*nrOfPackets - 1].header->len = header->len;
                packets[*nrOfPackets - 1].header->ts = header->ts;

                packets[*nrOfPackets - 1].packet = (uint8_t *)malloc(header->len);
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
        fprintf(stderr, "File already loaded into memory.");
        getchar();
        return pcap;
    }
}

uint32_t showNumberOfPackets(pcap_t *pcap, long *pos, struct pcap_pkthdr *header, const uint8_t *packet)
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

void listPackages(pcap_t *pcap, uint32_t *nrOfPackets)
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
                fprintf(stderr, "Error: Your ID-selection is out of range.");
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

void view(pcap_t *pcap, long *pos, uint32_t *nrOfPackets, struct pcap_pkthdr *header, const uint8_t *packet)
{
    if (pcap != NULL)
    {
        for (int i = 0; i < *nrOfPackets; i++)
        {
            printf("Packet %d:", i + 1);
            printf("\nCapture Length: %d", (int)packets[i].header->caplen);
            printf("\nLength: %d", packets[i].header->len);
            printf("\nCapture time: %f micro-seconds", (float)packets[i].header->ts.tv_usec);

            u_char *charPtr = (u_char *)packets[i].packet;

            printf("\n\n---Ethernet layer---\n\n");
            printf("Destination MAC Adress: %02x:%02x:%02x:%02x:%02x:%02x", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3), *(charPtr + 4), *(charPtr + 5));
            charPtr += 6;
            printf("\nSource MAC Adress: %02x:%02x:%02x:%02x:%02x:%02x", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3), *(charPtr + 4), *(charPtr + 5));
            charPtr += 6;
            unsigned short *shortPtr = (unsigned short *)charPtr;
            if (ntohs(*shortPtr) == 0x0800)
            {
                printf("\nEthertype: 0x0800 (IP)");
                printf("\n\n---IP Layer---\n");
                shortPtr += 1;
                charPtr = (u_char *)shortPtr;
                char ipVer = *charPtr >> 4;
                printf("\nIP-Version: %d", ipVer);
                char headerLength = *charPtr << 4;
                headerLength = headerLength >> 4;
                printf("\nIP Header Length: %d", headerLength * 4); //Number of 32-bit words, so we multiply by 4 to get the bytes it surmount to.
                charPtr += 1;
                printf("\nType-Of-Service (tos / DSCP|ECN): 0x%02x, (%d)", *charPtr, *charPtr);
                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                printf("\nIP-Length: %d", ntohs(*shortPtr));
                shortPtr += 1;
                printf("\nID: 0x%04x, (%d)", ntohs(*shortPtr), ntohs(*shortPtr));
                shortPtr += 1;
                charPtr = (u_char *)shortPtr;
                printf("\nFlag: 0x%03x", *charPtr);
                printf("\nFragment Offset: %02x", *(charPtr + 1));
                charPtr += 2;
                printf("\nTime-to-live (ttl): %d", *charPtr);
                charPtr += 1;
                if (*charPtr == 17) //UDP
                {
                    printf("\nIP-Protocol: %d (UDP)", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short *)charPtr;
                    printf("\nIP-Checksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    charPtr = (u_char *)shortPtr;
                    printf("\n\n---UDP Layer---\n");
                    printf("\nIP-source: %d.%d.%d.%d", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3));
                    charPtr += 4;
                    printf("\nIP-destination: %d.%d.%d.%d", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3));
                    charPtr += 4;
                    shortPtr = (unsigned short *)charPtr;
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
                    shortPtr = (unsigned short *)charPtr;
                    printf("\nIP-Checksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    charPtr = (u_char *)shortPtr;
                    printf("\n\n---TCP Layer---\n");
                    printf("\nIP-source: %d.%d.%d.%d", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3));
                    charPtr += 4;
                    printf("\nIP-destination: %d.%d.%d.%d", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3));
                    charPtr += 4;
                    shortPtr = (unsigned short *)charPtr;
                    printf("\nTCP Source Port: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nTCP Destination Port: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    unsigned int *intPtr = (unsigned int *)shortPtr;
                    printf("\nSequence Number: 0x%08x", ntohl(*intPtr));
                    intPtr += 1;
                    printf("\nAcknowledgement Number: 0x%08x", ntohl(*intPtr));
                    intPtr += 1;
                    charPtr = (u_char *)intPtr;
                    char firstFourBits = *charPtr >> 4;
                    printf("\nOffset: %d", (firstFourBits * 4)); //Number of 32-bit words, so we multiply by 4 to get the bytes it surmount to.
                    char lastFourBits = *charPtr << 4;
                    lastFourBits = lastFourBits >> 4;
                    printf("\nSize: %d", lastFourBits); //Should be 0.
                    charPtr += 1;
                    printf("\nFlag: 0x%03x", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short *)charPtr;
                    printf("\nWindow size: %d", ntohs(*shortPtr));
                    shortPtr += 1;
                    printf("\nChecksum: 0x%04x", ntohs(*shortPtr));
                }
                else if (*charPtr == 1) // ICMP
                {
                    printf("\nIP-Protocol: %d (ICMP)", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short *)charPtr;
                    printf("\nIP-Checksum: 0x%04x", ntohs(*shortPtr));
                    shortPtr += 1;
                    charPtr = (u_char *)shortPtr;
                    printf("\n\n---ICMP Layer---\n");
                    printf("\nIP-source: %d.%d.%d.%d", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3));
                    charPtr += 4;
                    printf("\nIP-destination: %d.%d.%d.%d", *charPtr, *(charPtr + 1), *(charPtr + 2), *(charPtr + 3));
                    charPtr += 4;
                    printf("\nType: %d", *charPtr);
                    charPtr += 1;
                    printf("\nCode: %d", *charPtr);
                    charPtr += 1;
                    shortPtr = (unsigned short *)charPtr;
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

void edit(uint32_t *nrOfPackets)
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
            if (userWantsToEdit("Capture length"))
            {
                bpf_u_int32 capLen = (bpf_u_int32)intFunction("Capture length", NULL, 1, 4294967295, true);
                packets[packetChoice].header->caplen = capLen;
            }
            if (userWantsToEdit("Total length"))
            {
                bpf_u_int32 totLen = (bpf_u_int32)intFunction("Total length", NULL, 1, 4294967295, true);
                packets[packetChoice].header->len = totLen;
            }
            if (userWantsToEdit("Capture time"))
            {
                __suseconds_t microSec = (__suseconds_t)intFunction("Capture time (micro seconds)", NULL, 1, 4294967295, true);
                packets[packetChoice].header->ts.tv_usec = microSec;
                packets[packetChoice].header->ts.tv_sec = (microSec / 1000000);
            }
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            u_char *charPtr = (u_char *)packets[packetChoice].packet;
            if (userWantsToEdit("Destination MAC adress"))
            {
                bool correctMAC = false;
                while (correctMAC == false)
                {
                    char macDest[19];
                    printf("Destination MAC Adress (WITH colons and in the form (XX:XX:XX:XX:XX:XX)): ");
                    fgets(macDest, 19, stdin);
                    for (int i = 0; i < 19; i++)
                    {
                        if (macDest[i] == '\n')
                        {
                            macDest[i] = '\0';
                        }
                    }
                    if (strlen(macDest) != 17)
                    {
                        printf("Incorrect length, try again.\n");
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
                            if (macDest[i * 3] > 102 || (macDest[i * 3] > 0 && macDest[i * 3] < 48) || (macDest[i * 3] > 70 && macDest[i * 3] < 97) || (macDest[i * 3] > 57 && macDest[i * 3] < 65))
                            {
                                correctMAC = false;
                            }
                            else if (macDest[(i * 3) + 1] > 102 || (macDest[(i * 3) + 1] > 0 && macDest[(i * 3) + 1] < 48) || (macDest[(i * 3) + 1] > 70 && macDest[(i * 3) + 1] < 97) || (macDest[(i * 3) + 1] > 57 && macDest[(i * 3) + 1] < 65))
                            {
                                correctMAC = false;
                            }
                        }
                        if (correctMAC == false)
                        {
                            printf("Incorrect input, please try again.\n");
                        }
                        else
                        {
                            int macD[6];
                            sscanf(macDest, "%x:%x:%x:%x:%x:%x", &macD[0], &macD[1], &macD[2], &macD[3], &macD[4], &macD[5]);
                            char finalMacDest[6];
                            for (int i = 0; i < 6; i++)
                            {
                                finalMacDest[i] = macD[i];
                            }
                            for (int i = 0; i < 6; i++)
                            {
                                *(charPtr + i) = finalMacDest[i];
                            }
                        }
                    }
                }
            }
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            charPtr += 6;
            if (userWantsToEdit("Source MAC adress"))
            {
                bool correctMAC = false;
                while (correctMAC == false)
                {
                    char macSource[19];
                    printf("Source MAC Adress (WITH colons and in the form (XX:XX:XX:XX:XX:XX)): ");
                    fgets(macSource, 19, stdin);
                    for (int i = 0; i < 19; i++)
                    {
                        if (macSource[i] == '\n')
                        {
                            macSource[i] = '\0';
                        }
                    }
                    if (strlen(macSource) != 17)
                    {
                        printf("Incorrect length, try again.\n");
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
                            if (macSource[i * 3] > 102 || (macSource[i * 3] > 0 && macSource[i * 3] < 48) || (macSource[i * 3] > 70 && macSource[i * 3] < 97) || (macSource[i * 3] > 57 && macSource[i * 3] < 65))
                            {
                                correctMAC = false;
                            }
                            else if (macSource[(i * 3) + 1] > 102 || (macSource[(i * 3) + 1] > 0 && macSource[(i * 3) + 1] < 48) || (macSource[(i * 3) + 1] > 70 && macSource[(i * 3) + 1] < 97) || (macSource[(i * 3) + 1] > 57 && macSource[(i * 3) + 1] < 65))
                            {
                                correctMAC = false;
                            }
                        }
                        if (correctMAC == false)
                        {
                            printf("Incorrect input, please try again.\n");
                        }
                        else
                        {
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
                        }
                    }
                }
            }
            /////////////////////////////////////////////////////////////
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
            ///////////////////////////////////////////////////////////
            printf("\n\n---IP-Layer---\n");
            printf("\nIP-version set to 4 - the only allowed.\n");
            charPtr += 2;
            short ihl = *charPtr;
            unsigned short *shortPtr = (unsigned short *)charPtr;
            if (userWantsToEdit("Ihl"))
            {
                ihl = shortFunction("Ihl", shortPtr, 5, 6, false, true);
                printf("%d", ihl);
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
                char finalIpVer = ipV;
                *charPtr = finalIpVer;
            }
            ////////////////////////////////////
            charPtr += 1;
            shortPtr = (unsigned short *)charPtr;
            if (userWantsToEdit("TOS"))
            {
                int dscp = (int)shortFunction("DSCP", shortPtr, 0, 63, false, true);
                int ECN = (int)shortFunction("ECN", shortPtr, 0, 3, false, true);
                printf("dscp: %d", dscp);
                printf("ECN: %d", ECN);
                dscp = dscp << 2;
                int finalDSF = dscp | ECN;
                unsigned char finalDsfAsChar = finalDSF;
                *charPtr = finalDsfAsChar;
            }
            ///////////////////////////////////
            charPtr += 1;
            shortPtr = (unsigned short *)charPtr;
            if (userWantsToEdit("Total length"))
            {
                shortFunction("Total length", shortPtr, (ihl * 4), 65535, false, false);
            }
            //////////////////////////////////////
            shortPtr += 1;
            if (userWantsToEdit("ID"))
            {
                shortFunction("ID", shortPtr, 0, 65535, false, false);
            }
            //////////////////////////////////////
            shortPtr += 1;
            if (userWantsToEdit("IP Flag"))
            {
                short flag = shortFunction("IP Flag", NULL, 0, 63, false, true);
                *shortPtr = htons(flag << 8);
            }
            //////////////////////////////////////
            shortPtr += 1;
            if (userWantsToEdit("Time-to-live"))
            {
                shortFunction("Time-to-live", shortPtr, 1, 255, true, false);
            }

            /////////////////////////////////////
            shortPtr += 1;
            charPtr = (unsigned char *)shortPtr;
            shortPtr = (unsigned short *)charPtr;
            printf("Header checksum 0x%04x left identical; edit does not have to handle changes in packet size.\n", ntohs(*shortPtr));
            /////////////////////////////////////
            shortPtr += 1;
            charPtr = (u_char *)shortPtr;
            if (userWantsToEdit("IP Source"))
            {
                bool correctIpSource = false;
                while (correctIpSource == false)
                {
                    char ipSource[17];
                    int dotIndexes[3] = {-1, -1, -1};
                    int nrOfDots = 0;
                    int previousInex = 0;
                    bool noLetters = true;
                    bool correctIpStructure = true;
                    printf("IP-Source (In the form X.X.X.X where 0 < X < 1000 and WITH dots): ");
                    fgets(ipSource, 17, stdin);
                    for (int i = 0; i < strlen(ipSource) && noLetters == true; i++)
                    {
                        if (ipSource[i] == '\n')
                        {
                            ipSource[i] = '\0';
                        }
                        if (ipSource[i] == '.' && i > 0)
                        {
                            nrOfDots++;
                            if (nrOfDots <= 3)
                            {
                                dotIndexes[nrOfDots - 1] = i;
                            }
                        }
                        else if (!(isdigit(ipSource[i])) && ipSource[i] != '\0')
                        {
                            noLetters = false;
                        }
                    }
                    if (nrOfDots == 3)
                    {
                        for (int i = 0; i < 2; i++)
                        {
                            if (dotIndexes[i + 1] - dotIndexes[i] == 1 || dotIndexes[i + 1] - dotIndexes[i] > 4 || (strlen(ipSource) - 1) - dotIndexes[2] > 3)
                            {
                                correctIpStructure = false;
                            }
                        }
                    }

                    if (strlen(ipSource) <= 15 && strlen(ipSource) >= 7 && nrOfDots == 3 && noLetters == true && correctIpStructure == true)
                    {
                        char temp1[3];
                        char temp2[3];
                        char temp3[3];
                        char temp4[3];
                        int index = 0;
                        for (int i = 0; i < dotIndexes[0]; i++)
                        {
                            temp1[index] = ipSource[i];
                            index++;
                        }
                        temp1[index] = '\0';
                        int nr = atoi(temp1);
                        u_char *ch = (u_char *)&nr;
                        *charPtr = *ch;
                        charPtr += 1;
                        index = 0;
                        for (int i = dotIndexes[0] + 1; i < dotIndexes[1]; i++)
                        {
                            temp2[index] = ipSource[i];
                            index++;
                        }
                        temp2[index] = '\0';
                        nr = atoi(temp2);
                        *charPtr = *ch;
                        charPtr += 1;
                        index = 0;
                        for (int i = dotIndexes[1] + 1; i < dotIndexes[2]; i++)
                        {
                            temp3[index] = ipSource[i];
                            index++;
                        }
                        temp3[index] = '\0';
                        nr = atoi(temp3);
                        *charPtr = *ch;
                        charPtr += 1;
                        index = 0;
                        for (int i = dotIndexes[2] + 1; i < strlen(ipSource); i++)
                        {
                            temp4[index] = ipSource[i];
                            index++;
                        }
                        temp4[index] = '\0';
                        nr = atoi(temp4);
                        *charPtr = *ch;
                        charPtr += 1;
                        correctIpSource = true;
                    }
                }
            }
            else
            {
                charPtr += 4;
            }
            ///////////////////////////////////////////////////////////////////////////////////////
            if (userWantsToEdit("IP destination"))
            {
                bool correctIpDest = false;
                while (correctIpDest == false)
                {
                    char ipDest[17];
                    int dotIndexes[3] = {-1, -1, -1};
                    int nrOfDots = 0;
                    bool noLetters = true;
                    bool correctIpStructure = true;
                    printf("IP-Destination (In the form X.X.X.X where 0 < X < 1000 and WITH dots): ");
                    fgets(ipDest, 17, stdin);
                    for (int i = 0; i < strlen(ipDest) && noLetters == true; i++)
                    {
                        if (ipDest[i] == '\n')
                        {
                            ipDest[i] = '\0';
                        }
                        if (ipDest[i] == '.' && i > 0)
                        {
                            nrOfDots++;
                            if (nrOfDots <= 3)
                            {
                                dotIndexes[nrOfDots - 1] = i;
                            }
                        }
                        else if (!(isdigit(ipDest[i])) && ipDest[i] != '\0')
                        {
                            noLetters = false;
                        }
                    }
                    if (nrOfDots == 3)
                    {
                        for (int i = 0; i < 2; i++)
                        {
                            if (dotIndexes[i + 1] - dotIndexes[i] == 1 || dotIndexes[i + 1] - dotIndexes[i] > 4 || (strlen(ipDest) - 1) - dotIndexes[2] > 3)
                            {
                                correctIpStructure = false;
                            }
                        }
                    }

                    if (strlen(ipDest) <= 15 && strlen(ipDest) >= 7 && nrOfDots == 3 && noLetters == true && correctIpStructure == true)
                    {
                        char temp1[4];
                        char temp2[4];
                        char temp3[4];
                        char temp4[4];
                        int index = 0;
                        for (int i = 0; i < dotIndexes[0]; i++)
                        {

                            temp1[index] = ipDest[i];
                            index++;
                        }
                        temp1[index] = '\0';
                        int nr = atoi(temp1);
                        u_char *ch = (u_char *)&nr;
                        *charPtr = *ch;
                        charPtr += 1;
                        index = 0;
                        for (int i = dotIndexes[0] + 1; i < dotIndexes[1]; i++)
                        {
                            temp2[index] = ipDest[i];
                            index++;
                        }
                        temp2[index] = '\0';
                        nr = atoi(temp2);
                        *charPtr = *ch;
                        charPtr += 1;
                        index = 0;
                        for (int i = dotIndexes[1] + 1; i < dotIndexes[2]; i++)
                        {
                            temp3[index] = ipDest[i];
                            index++;
                        }
                        temp3[index] = '\0';
                        nr = atoi(temp3);
                        *charPtr = *ch;
                        charPtr += 1;
                        index = 0;
                        for (int i = dotIndexes[2] + 1; i < strlen(ipDest); i++)
                        {
                            temp4[index] = ipDest[i];
                            index++;
                        }
                        temp4[index] = '\0';
                        nr = atoi(temp4);
                        *charPtr = *ch;
                        charPtr += 1;
                        correctIpDest = true;
                    }
                }
            }
            else
            {
                charPtr += 4;
            }
            ////////////////////////////////////////////////////////////////
            charPtr -= 11;      //Moving to transport protocol identifier
            if (*charPtr == 17) //UDP
            {
                printf("\n---UDP Layer---\n");
                charPtr += 11; //Moving back
                shortPtr = (unsigned short *)charPtr;
                if (userWantsToEdit("Source port"))
                {
                    shortFunction("Source port", shortPtr, 1, 65535, false, false);
                }
                /////////////////////////////////////////////////////////
                shortPtr += 1;
                if (userWantsToEdit("Destination port"))
                {
                    shortFunction("Destination port", shortPtr, 1, 65535, false, false);
                }
                //////////////////////////////////////////////////////////
                shortPtr += 1;
                if (userWantsToEdit("UDP length"))
                {
                    shortFunction("UDP length", shortPtr, 1, (65535 - (ihl * 4) - 8), false, false);
                }

                shortPtr += 1;
                printf("UDP checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));
                printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));
                printf("\nPress enter to return to menu.");
                getchar();
            }
            else if (*charPtr == 6) //TCP
            {
                printf("\n---TCP Layer---\n\n");
                charPtr += 11; //Moving back
                shortPtr = (unsigned short *)charPtr;
                if (userWantsToEdit("Source port"))
                {
                    shortFunction("Source port", shortPtr, 1, 65535, false, false);
                }
                //////////////////////////////////////////////////////
                shortPtr += 1;
                if (userWantsToEdit("Destination port"))
                {
                    shortFunction("Destination port", shortPtr, 1, 65535, false, false);
                }

                shortPtr += 1;
                ///////////////////////////////////////////////////////
                unsigned int *intPtr = (unsigned int *)shortPtr;
                if (userWantsToEdit("Sequence number"))
                {
                    intFunction("Sequence number", intPtr, 0, 4294967295, false);
                }
                intPtr += 1;
                ////////////////////////////////////////////////////////
                if (userWantsToEdit("Acknowledgment number"))
                {
                    intFunction("Acknowledgment number", intPtr, 0, 4294967295, false);
                }
                intPtr += 1;
                ////////////////////////////////////////////////////
                charPtr = (u_char *)intPtr;
                unsigned short tcpHeaderLength = -1;
                bool correctTcpHeaderLength = false;
                while (correctTcpHeaderLength == false)
                {
                    bool isANumber = true;
                    char check[4];
                    printf("IHL size (5 - 15): ");
                    fgets(check, 4, stdin);
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
                        tcpHeaderLength = atoi(check);

                        if (tcpHeaderLength >= 5 && tcpHeaderLength <= 15)
                        {
                            correctTcpHeaderLength = true;
                        }
                    }
                    if (!correctTcpHeaderLength || !isANumber)
                    {
                        printf("Incorrect input, please try again.\n");
                    }
                }
                u_char *temp = (u_char *)&tcpHeaderLength;
                *temp = *temp << 4;
                *charPtr = *temp;
                //////////////////////////////////////////////////
                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                if (userWantsToEdit("TCP Flag"))
                {
                    shortFunction("TCP Flag", shortPtr, 0, 63, true, false);
                }
                charPtr += 1;
                ////////////////////////////////////////////////
                shortPtr = (unsigned short *)charPtr;
                if (userWantsToEdit("Window size value"))
                {
                    shortFunction("Window size value", shortPtr, 1, 65535, false, false);
                }
                shortPtr += 1;
                ///////////////////////////////////////////////
                printf("TCP Header checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));
                printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));
                printf("\nPress enter to return to menu.");
                getchar();
            }
            if (*charPtr == 1) //ICMP
            {
                printf("\n---ICMP Layer---\n\n");
                charPtr += 11; //Moving back
                shortPtr = (unsigned short *)charPtr;
                if (userWantsToEdit("Type"))
                {
                    shortFunction("Type", shortPtr, 0, 255, true, false);
                }
                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                if (userWantsToEdit("Code"))
                {
                    shortFunction("Code", shortPtr, 0, 255, true, false);
                }
                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                printf("ICMP checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));
                shortPtr += 1;
                if (userWantsToEdit("ID"))
                {
                    shortFunction("ID", shortPtr, 0, 65535, false, false);
                }
                shortPtr += 1;
                if (userWantsToEdit("Sequence number"))
                {
                    shortFunction("Sequence number", shortPtr, 0, 65535, false, false);
                }
                printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));
                printf("\nPress enter to return to menu.");
                getchar();
            }
            else
            {
                printf("Transport protocol not of type UDP, TCP or ICMP, remaining packet not editable.");
                printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));
                printf("\nPress enter to return to menu.");
                getchar();
            }
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

void addInsert(uint32_t *nrOfPackets)
{
    if (*nrOfPackets > 0)
    {
        uint32_t choice = -1;
        uint32_t index = -1;
        bool correctChoice = false;
        printf("There are currently %d packets loaded into memory.", *nrOfPackets);
        printf("\nWould you like to add (append at the end) or insert (at a specific index)? (1 - add, 2 - insert): ");
        scanf("%d", &choice);
        getchar();
        if (choice == 1)
        {
            printf("The packet will be appended in memory after last packet %d.\n", *nrOfPackets);
            correctChoice = true;
        }
        else if (choice == 2)
        {
            printf("At what index would you like to insert the packet? The following range is possible: 0 - %d: ", *(nrOfPackets)-2);
            scanf("%d", &index);
            getchar();
            if (index >= 0 && index <= *(nrOfPackets)-2)
            {
                correctChoice = true;
            }
        }
        if (correctChoice == true)
        {
            bool correctProtocol = false;
            unsigned short protocol = -1;
            while (correctProtocol == false)
            {
                printf("Transport Protocol for the packet (ICMP - 1, TCP = 6, UDP - 17): ");
                scanf("%hd", &protocol);
                getchar();
                if (protocol == 1 || protocol == 6 || protocol == 17)
                {
                    correctProtocol = true;
                }
                else
                {
                    printf("Incorrect input, please try again.");
                }
            }
            unsigned int minPacketSize = -1;
            if (protocol == 1) // ICMP
            {
                minPacketSize = (14 + 20 + 8);
            }
            else if (protocol == 6) // TCP
            {
                minPacketSize = (14 + 20 + 20);
            }
            else // UDP
            {
                minPacketSize = (14 + 20 + 8);
            }

            ++(*nrOfPackets);
            packets = realloc(packets, *nrOfPackets * sizeof(Packets));
            packets[*nrOfPackets - 1].header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr *));

            bpf_u_int32 capLen = (bpf_u_int32)intFunction("Capture length", NULL, minPacketSize, 4294967295, true);
            packets[*nrOfPackets - 1].header->caplen = capLen;

            bpf_u_int32 totLen = (bpf_u_int32)intFunction("Total length", NULL, minPacketSize, 4294967295, true);
            packets[*nrOfPackets - 1].header->len = totLen;
            unsigned int payloadSize = totLen - minPacketSize;

            __suseconds_t microSec = (__suseconds_t)intFunction("Capture time (micro seconds)", NULL, 1, 4294967295, true);
            packets[*nrOfPackets - 1].header->ts.tv_usec = microSec;
            packets[*nrOfPackets - 1].header->ts.tv_sec = (microSec / 1000000);

            packets[*nrOfPackets - 1].packet = (uint8_t *)malloc(totLen);
            u_char *charPtr = (u_char *)packets[*nrOfPackets - 1].packet;

            bool correctMAC = false;
            while (correctMAC == false)
            {
                char macDest[19];
                printf("Destination MAC Adress (WITH colons and in the form (XX:XX:XX:XX:XX:XX)): ");
                fgets(macDest, 19, stdin);
                for (int i = 0; i < 19; i++)
                {
                    if (macDest[i] == '\n')
                    {
                        macDest[i] = '\0';
                    }
                }
                if (strlen(macDest) != 17)
                {
                    printf("Incorrect length, try again.\n");
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
                        if (macDest[i * 3] > 102 || (macDest[i * 3] > 0 && macDest[i * 3] < 48) || (macDest[i * 3] > 70 && macDest[i * 3] < 97) || (macDest[i * 3] > 57 && macDest[i * 3] < 65))
                        {
                            correctMAC = false;
                        }
                        else if (macDest[(i * 3) + 1] > 102 || (macDest[(i * 3) + 1] > 0 && macDest[(i * 3) + 1] < 48) || (macDest[(i * 3) + 1] > 70 && macDest[(i * 3) + 1] < 97) || (macDest[(i * 3) + 1] > 57 && macDest[(i * 3) + 1] < 65))
                        {
                            correctMAC = false;
                        }
                    }
                    if (correctMAC == false)
                    {
                        printf("Incorrect input, please try again.\n");
                    }
                    else
                    {
                        int macD[6];
                        sscanf(macDest, "%x:%x:%x:%x:%x:%x", &macD[0], &macD[1], &macD[2], &macD[3], &macD[4], &macD[5]);
                        char finalMacDest[6];
                        for (int i = 0; i < 6; i++)
                        {
                            finalMacDest[i] = macD[i];
                        }
                        for (int i = 0; i < 6; i++)
                        {
                            *(charPtr + i) = finalMacDest[i];
                        }
                    }
                }
            }

            charPtr += 6;

            correctMAC = false;
            while (correctMAC == false)
            {
                char macSource[19];
                printf("Source MAC Adress (WITH colons and in the form (XX:XX:XX:XX:XX:XX)): ");
                fgets(macSource, 19, stdin);
                for (int i = 0; i < 19; i++)
                {
                    if (macSource[i] == '\n')
                    {
                        macSource[i] = '\0';
                    }
                }
                if (strlen(macSource) != 17)
                {
                    printf("Incorrect length, try again.\n");
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
                        if (macSource[i * 3] > 102 || (macSource[i * 3] > 0 && macSource[i * 3] < 48) || (macSource[i * 3] > 70 && macSource[i * 3] < 97) || (macSource[i * 3] > 57 && macSource[i * 3] < 65))
                        {
                            correctMAC = false;
                        }
                        else if (macSource[(i * 3) + 1] > 102 || (macSource[(i * 3) + 1] > 0 && macSource[(i * 3) + 1] < 48) || (macSource[(i * 3) + 1] > 70 && macSource[(i * 3) + 1] < 97) || (macSource[(i * 3) + 1] > 57 && macSource[(i * 3) + 1] < 65))
                        {
                            correctMAC = false;
                        }
                    }
                    if (correctMAC == false)
                    {
                        printf("Incorrect input, please try again.\n");
                    }
                    else
                    {
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
                    }
                }
            }

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

            printf("\n\n---IP-Layer---\n");
            printf("\nIP-version set to 4 - the only allowed.\n");
            charPtr += 2;
            short ihl = *charPtr;
            unsigned short *shortPtr = (unsigned short *)charPtr;

            ihl = shortFunction("Ihl", shortPtr, 5, 6, false, true);
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
            char finalIpVer = ipV;
            *charPtr = finalIpVer;

            charPtr += 1;
            shortPtr = (unsigned short *)charPtr;
            int dscp = (int)shortFunction("DSCP", shortPtr, 0, 63, false, true);
            int ECN = (int)shortFunction("ECN", shortPtr, 0, 3, false, true);
            dscp = dscp << 2;
            int finalDSF = dscp | ECN;
            unsigned char finalDsfAsChar = finalDSF;
            *charPtr = finalDsfAsChar;

            charPtr += 1;
            shortPtr = (unsigned short *)charPtr;
            shortFunction("Total length", shortPtr, (ihl * 4), 65535, false, false);

            shortPtr += 1;
            shortFunction("ID", shortPtr, 0, 65535, false, false);

            shortPtr += 1;
            short flag = shortFunction("IP Flag", NULL, 0, 63, false, true);
            *shortPtr = htons(flag << 8);

            shortPtr += 1;
            shortFunction("Time-to-live", shortPtr, 1, 255, true, false);

            ///////////////////////////////////// CHECKSUM TO BE CODED
            shortPtr += 1;
            charPtr = (unsigned char *)shortPtr;
            shortPtr = (unsigned short *)charPtr;
            *shortPtr = 0;
            printf("Header checksum PLACEHOLDER\n");
            /////////////////////////////////////
            shortPtr += 1;
            charPtr = (u_char *)shortPtr;

            bool correctIpSource = false;
            while (correctIpSource == false)
            {
                char ipSource[17];
                int dotIndexes[3] = {-1, -1, -1};
                int nrOfDots = 0;
                int previousInex = 0;
                bool noLetters = true;
                bool correctIpStructure = true;
                printf("IP-Source (In the form X.X.X.X where 0 < X < 1000 and WITH dots): ");
                fgets(ipSource, 17, stdin);
                for (int i = 0; i < strlen(ipSource) && noLetters == true; i++)
                {
                    if (ipSource[i] == '\n')
                    {
                        ipSource[i] = '\0';
                    }
                    if (ipSource[i] == '.' && i > 0)
                    {
                        nrOfDots++;
                        if (nrOfDots <= 3)
                        {
                            dotIndexes[nrOfDots - 1] = i;
                        }
                    }
                    else if (!(isdigit(ipSource[i])) && ipSource[i] != '\0')
                    {
                        noLetters = false;
                    }
                }
                if (nrOfDots == 3)
                {
                    for (int i = 0; i < 2; i++)
                    {
                        if (dotIndexes[i + 1] - dotIndexes[i] == 1 || dotIndexes[i + 1] - dotIndexes[i] > 4 || (strlen(ipSource) - 1) - dotIndexes[2] > 3)
                        {
                            correctIpStructure = false;
                        }
                    }
                }

                if (strlen(ipSource) <= 15 && strlen(ipSource) >= 7 && nrOfDots == 3 && noLetters == true && correctIpStructure == true)
                {
                    char temp1[3];
                    char temp2[3];
                    char temp3[3];
                    char temp4[3];
                    int index = 0;
                    for (int i = 0; i < dotIndexes[0]; i++)
                    {
                        temp1[index] = ipSource[i];
                        index++;
                    }
                    temp1[index] = '\0';
                    int nr = atoi(temp1);
                    u_char *ch = (u_char *)&nr;
                    *charPtr = *ch;
                    charPtr += 1;
                    index = 0;
                    for (int i = dotIndexes[0] + 1; i < dotIndexes[1]; i++)
                    {
                        temp2[index] = ipSource[i];
                        index++;
                    }
                    temp2[index] = '\0';
                    nr = atoi(temp2);
                    *charPtr = *ch;
                    charPtr += 1;
                    index = 0;
                    for (int i = dotIndexes[1] + 1; i < dotIndexes[2]; i++)
                    {
                        temp3[index] = ipSource[i];
                        index++;
                    }
                    temp3[index] = '\0';
                    nr = atoi(temp3);
                    *charPtr = *ch;
                    charPtr += 1;
                    index = 0;
                    for (int i = dotIndexes[2] + 1; i < strlen(ipSource); i++)
                    {
                        temp4[index] = ipSource[i];
                        index++;
                    }
                    temp4[index] = '\0';
                    nr = atoi(temp4);
                    *charPtr = *ch;
                    charPtr += 1;
                    correctIpSource = true;
                }
            }

            bool correctIpDest = false;
            while (correctIpDest == false)
            {
                char ipDest[17];
                int dotIndexes[3] = {-1, -1, -1};
                int nrOfDots = 0;
                bool noLetters = true;
                bool correctIpStructure = true;
                printf("IP-Destination (In the form X.X.X.X where 0 < X < 1000 and WITH dots): ");
                fgets(ipDest, 17, stdin);
                for (int i = 0; i < strlen(ipDest) && noLetters == true; i++)
                {
                    if (ipDest[i] == '\n')
                    {
                        ipDest[i] = '\0';
                    }
                    if (ipDest[i] == '.' && i > 0)
                    {
                        nrOfDots++;
                        if (nrOfDots <= 3)
                        {
                            dotIndexes[nrOfDots - 1] = i;
                        }
                    }
                    else if (!(isdigit(ipDest[i])) && ipDest[i] != '\0')
                    {
                        noLetters = false;
                    }
                }
                if (nrOfDots == 3)
                {
                    for (int i = 0; i < 2; i++)
                    {
                        if (dotIndexes[i + 1] - dotIndexes[i] == 1 || dotIndexes[i + 1] - dotIndexes[i] > 4 || (strlen(ipDest) - 1) - dotIndexes[2] > 3)
                        {
                            correctIpStructure = false;
                        }
                    }
                }

                if (strlen(ipDest) <= 15 && strlen(ipDest) >= 7 && nrOfDots == 3 && noLetters == true && correctIpStructure == true)
                {
                    char temp1[4];
                    char temp2[4];
                    char temp3[4];
                    char temp4[4];
                    int index = 0;
                    for (int i = 0; i < dotIndexes[0]; i++)
                    {

                        temp1[index] = ipDest[i];
                        index++;
                    }
                    temp1[index] = '\0';
                    int nr = atoi(temp1);
                    u_char *ch = (u_char *)&nr;
                    *charPtr = *ch;
                    charPtr += 1;
                    index = 0;
                    for (int i = dotIndexes[0] + 1; i < dotIndexes[1]; i++)
                    {
                        temp2[index] = ipDest[i];
                        index++;
                    }
                    temp2[index] = '\0';
                    nr = atoi(temp2);
                    *charPtr = *ch;
                    charPtr += 1;
                    index = 0;
                    for (int i = dotIndexes[1] + 1; i < dotIndexes[2]; i++)
                    {
                        temp3[index] = ipDest[i];
                        index++;
                    }
                    temp3[index] = '\0';
                    nr = atoi(temp3);
                    *charPtr = *ch;
                    charPtr += 1;
                    index = 0;
                    for (int i = dotIndexes[2] + 1; i < strlen(ipDest); i++)
                    {
                        temp4[index] = ipDest[i];
                        index++;
                    }
                    temp4[index] = '\0';
                    nr = atoi(temp4);
                    *charPtr = *ch;
                    charPtr += 1;
                    correctIpDest = true;
                }
            }

            charPtr -= 11; //Moving to transport protocol identifier
            *charPtr = *((u_char *)&protocol);

            if (*charPtr == 17) //UDP
            {
                printf("\n---UDP Layer---\n");
                charPtr += 11; //Moving back

                shortPtr = (unsigned short *)charPtr;
                shortFunction("Source port", shortPtr, 1, 65535, false, false);

                shortPtr += 1;
                shortFunction("Destination port", shortPtr, 1, 65535, false, false);

                shortPtr += 1;
                shortFunction("UDP length", shortPtr, 1, (65535 - (ihl * 4) - 8), false, false);

                shortPtr += 1;
                //printf("UDP checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));
                //printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));

                printf("\nPacket added!");
                printf("\nPress enter to return to menu.");
                getchar();
            }
            else if (*charPtr == 6) //TCP
            {
                printf("\n---TCP Layer---\n\n");
                charPtr += 11; //Moving back

                shortPtr = (unsigned short *)charPtr;
                shortFunction("Source port", shortPtr, 1, 65535, false, false);

                shortPtr += 1;
                shortFunction("Destination port", shortPtr, 1, 65535, false, false);

                shortPtr += 1;
                unsigned int *intPtr = (unsigned int *)shortPtr;
                intFunction("Sequence number", intPtr, 0, 4294967295, false);

                intPtr += 1;
                intFunction("Acknowledgment number", intPtr, 0, 4294967295, false);

                intPtr += 1;
                charPtr = (u_char *)intPtr;
                unsigned short tcpHeaderLength = -1;
                bool correctTcpHeaderLength = false;
                while (correctTcpHeaderLength == false)
                {
                    bool isANumber = true;
                    char check[4];
                    printf("IHL size (5 - 15): ");
                    fgets(check, 4, stdin);
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
                        tcpHeaderLength = atoi(check);

                        if (tcpHeaderLength >= 5 && tcpHeaderLength <= 15)
                        {
                            correctTcpHeaderLength = true;
                        }
                    }
                    if (!correctTcpHeaderLength || !isANumber)
                    {
                        printf("Incorrect input, please try again.\n");
                    }
                }
                u_char *temp = (u_char *)&tcpHeaderLength;
                *temp = *temp << 4;
                *charPtr = *temp;

                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                shortFunction("TCP Flag", shortPtr, 0, 63, true, false);

                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                shortFunction("Window size value", shortPtr, 1, 65535, false, false);

                shortPtr += 1;
                ///////////////////////////////////////////////
                //printf("TCP Header checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));
                //printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));
                printf("\nPacket added!");
                printf("\nPress enter to return to menu.");
                getchar();
            }
            else if (*charPtr == 1) //ICMP
            {
                printf("\n---ICMP Layer---\n\n");
                charPtr += 11; //Moving back

                shortPtr = (unsigned short *)charPtr;
                shortFunction("Type", shortPtr, 0, 255, true, false);

                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                shortFunction("Code", shortPtr, 0, 255, true, false);

                charPtr += 1;
                shortPtr = (unsigned short *)charPtr;
                //printf("ICMP checksum 0x%04x left identical; edit does not have to handle changes in packet size.", ntohs(*shortPtr));

                shortPtr += 1;
                shortFunction("ID", shortPtr, 0, 65535, false, false);

                shortPtr += 1;
                shortFunction("Sequence number", shortPtr, 0, 65535, false, false);

                //printf("\nPacket %d has been edited, use view -or list-function from the menu to view your changes.", (packetChoice + 1));
                printf("\nPacket has been added.");
                printf("\nPress enter to return to menu.");
                getchar();
            }
        }
        else
        {
            fprintf(stderr, "Error; input out of bounds");
            getchar();
        }
    }
    else
    {
        fprintf(stderr, "Error; no file loaded into memory.");
        getchar();
    }
}

short shortFunction(char *fieldToEdit, unsigned short *shortPtr, unsigned int lowerLimit, unsigned int upperLimit, bool convertToChar, bool onlyReturn)
{
    bool correctValue = false;
    unsigned short value = -1;

    while (correctValue == false)
    {
        bool isANumber = true;
        char check[12];
        printf("%s (%d - %d): ", fieldToEdit, lowerLimit, upperLimit);
        fgets(check, 7, stdin);
        for (int i = 0; i < 7; i++)
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
            value = atoi(check);

            if (value >= lowerLimit && value <= upperLimit)
            {
                correctValue = true;
            }
        }
        if (!correctValue || !isANumber)
        {
            printf("Incorrect input, please try again.\n");
        }
        else
        {
            if (!onlyReturn)
            {
                if (convertToChar)
                {
                    unsigned char *charPtr = (unsigned char *)shortPtr;
                    *charPtr = *((u_char *)&value);
                }
                else
                {
                    *shortPtr = htons(value);
                }
            }
        }
    }
    return value;
}

int intFunction(char *fieldToEdit, unsigned int *intPtr, unsigned long lowerLimit, unsigned long upperLimit, bool onlyReturn)
{
    bool correctValue = false;
    unsigned int value = -1;

    while (correctValue == false)
    {
        bool isANumber = true;
        char check[12];
        printf("%s (%ld - %ld): ", fieldToEdit, lowerLimit, upperLimit);
        fgets(check, 12, stdin);
        for (int i = 0; i < 12; i++)
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
            value = atoi(check);

            if (value >= lowerLimit && value <= upperLimit)
            {
                correctValue = true;
            }
        }
        if (!correctValue || !isANumber)
        {
            printf("Incorrect input, please try again.\n");
        }
        else
        {
            if (!onlyReturn)
            {
                *intPtr = htonl(value);
            }
        }
    }
    return value;
}

bool userWantsToEdit(char *fieldtoEdit)
{
    bool correctAnswer = false;
    unsigned short answer = -1;
    while (correctAnswer == false)
    {
        bool isANumber = true;
        char check[3];
        printf("Would you like to edit %s? (1 = Yes, 2 = No): ", fieldtoEdit);
        fgets(check, 3, stdin);
        for (int i = 0; i < 3; i++)
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
            answer = atoi(check);

            if (answer >= 1 && answer <= 2)
            {
                correctAnswer = true;
            }
        }
        if (!correctAnswer || !isANumber)
        {
            printf("Incorrect input, please try again.\n");
        }
    }
    if (answer == 1)
    {
        return true;
    }
    else
    {
        return false;
    }
}