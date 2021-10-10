#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include "aes.h"

uint8_t key[16] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98};

uint8_t text[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

void recvData(int new_socket, char* filename) {
    FILE* file = fopen(filename, "wb");

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    memset(text, 0, 16);
    int dataLength;
    int fileSize = 0;

    while(dataLength = recv(new_socket, text, 16, 0) == 16){
        int i;
        AES_ECB_decrypt(&ctx, text);

        // debug
        // for(i=0;i<16;i++){
        //     printf("%x ", text[i]);
        // }

        fwrite(text, sizeof(uint8_t), 16, file);

        memset(text, 0, 16);
        fileSize = fileSize + dataLength;
        printf("%d\n", fileSize);
    }

    fclose(file);
    // truncate(filename, fileSize - text[0]);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("File is not specified !\n");
        return 0;
    }

    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    clock_t start;
    start = clock();

    char* filename = argv[1];
    // printf("%s", filename);

    // read(sock , filename, 1024);
    recvData(sock, filename);
    
    printf("File message received\n");

    clock_t end;
    end = clock();
    printf("--- %lf seconds ---", ((double)end-start)/CLOCKS_PER_SEC);

    return 0;
}