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

int sendData(int new_socket, char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("File not found\n");
        exit(1);
    }
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    memset(text, 0, 16);
    int dataLength;
    int endLength = 0;

    while (dataLength = fread(text, sizeof(uint8_t), 16, file) > 0) {
        int i;
        AES_ECB_encrypt(&ctx, text);

        // debug
        // for(i=0;i<16;i++){
        //     printf("%x ", text[i]);
        // }
        
        send(new_socket, text, 16, 0);
        memset(text, 0, 16);
        endLength = 16 - dataLength;
        // printf("%d\n", endLength);
    }

    fclose(file);
    send(new_socket, &endLength, 1, 0);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("File is not specified !\n");
        return 0;
    }

    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( 8080 );
    
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,(socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    clock_t start;
    start = clock();
    
    char* filename = argv[1];
    // printf("%s", filename);

    //send(new_socket, filename, 1024, 0);
    sendData(new_socket, filename);

    printf("File message sent\n");

    clock_t end;
    end = clock();
    printf("--- %lf seconds ---", ((double)end-start)/CLOCKS_PER_SEC);

    return 0;
}