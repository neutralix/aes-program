#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>

uint8_t key[16] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98};

uint8_t roundKey[16];

uint32_t* expanded_key;

uint8_t text[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

uint32_t rCon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

uint32_t* keyExpansion() {
    int i;
    uint32_t* w = (uint32_t*)malloc(44 * sizeof(uint32_t));
    for (i = 0; i < 4; i++) {
        *(w + i) = ((key[4*i+0]<<24) + (key[4*i+1]<<16) + (key[4*i+2]<<8) + key[4*i+3]);
    }
    for (i = 4; i < 44; i++){
        uint32_t temp = w[i - 1];
        
        if (i % 4 == 0){
            // #RotWord
            uint8_t x0 = (temp >> 16) & 0xFF;
            uint8_t x1 = (temp >> 8) & 0xFF;
            uint8_t x2 = temp & 0xFF;
            uint8_t x3 = (temp >> 24);

            // #SubWord & XOR RCon
            uint8_t y0 = sbox[x0] ^ rCon[(i/4)-1];
            uint8_t y1 = sbox[x1];
            uint8_t y2 = sbox[x2];
            uint8_t y3 = sbox[x3];

            temp = ((y0 << 24) + (y1 << 16) + (y2 << 8) + y3);
        }
        w[i] = w[i-4] ^ temp;
    }
    return w;
};

void transposeText(){
    int i, j;
    uint8_t temp;
    for(i=0; i<4; i++){
        for(j=i+1; j<4; j++){
            temp = text[i*4+j];
            text[i*4+j] = text[j*4+i];
            text[j*4+i] = temp;
        }
    }
}

void transposeRoundKey(){
    int i, j;
    uint8_t temp;
    for(i=0; i<4; i++){
        for(j=i+1; j<4; j++){
            temp = roundKey[i*4+j];
            roundKey[i*4+j] = roundKey[j*4+i];
            roundKey[j*4+i] = temp;
        }
    }
}

void subBytes() {
    uint8_t i=0;
    for (i = 0; i < 16; i++){
        text[i] = sbox[text[i]];
    }
};

void shiftRow() {
    int i;
    uint8_t temp,temp2;

    temp = text[4];
    for(i=4; i<7;i++){
        text[i] = text[i + 1];
    }
    text[7] = temp;

    temp = text[8];
    temp2 = text[9];
    for(i=8; i<10;i++){
        text[i] = text[i + 2];
    }
    text[10] = temp;
    text[11] = temp2;

    temp = text[15];
    for(i=15; i>12;i--){
        text[i] = text[i - 1];
    }
    text[12] = temp;
};

uint8_t multiply(uint8_t collumn, int multiplier) {
    if(multiplier==2){
        uint8_t msb = collumn & 0x80;
        collumn = collumn << 1; 
        if(msb == 0x80){
            collumn = collumn ^ 0x1b;        
        }
    }
    else if (multiplier==3) {
        collumn = collumn ^ multiply(collumn, 2);
    }

    return collumn;
}

void mixCollumn() {
    int i;
    for(i=0;i<4;i++) {
        uint8_t collumn[4] = {text[i], text[4+i], text[8+i], text[12+i]};
        text[i] = multiply(collumn[0], 2) ^ multiply(collumn[1], 3) ^ collumn[2] ^ collumn[3];
        text[4+i] = collumn[0] ^ multiply(collumn[1], 2) ^ multiply(collumn[2], 3) ^ collumn[3];
        text[8+i] = collumn[0] ^ collumn[1] ^ multiply(collumn[2], 2) ^ multiply(collumn[3], 3);
        text[12+i] = multiply(collumn[0], 3) ^ collumn[1] ^ collumn[2] ^ multiply(collumn[3], 2);
    }
}

void addRoundKey(int round) {
    int i;
    for (i=0;i<4;i++){
        uint32_t row = expanded_key[ i + (round*4) ];
        uint8_t x0 = (row >> 24);
        uint8_t x1 = (row >> 16) & 0xFF;
        uint8_t x2 = (row >> 8) & 0xFF;
        uint8_t x3 = row & 0xFF;
        
        roundKey[i*4+0] = x0;
        roundKey[i*4+1] = x1;
        roundKey[i*4+2] = x2;
        roundKey[i*4+3] = x3;
    }
    transposeRoundKey();
    for (i=0;i<16;i++){
        text[i] =  text[i]^roundKey[i];
    }
}

void encrypt(){
    int i;

    transposeText();
    
    // initial round
    addRoundKey(0);

    // round 1-9
    for (i=1;i<10;i++) {
        subBytes();
        shiftRow();
        mixCollumn();
        addRoundKey(i);
    }

    // round 10
    subBytes();
    shiftRow();
    addRoundKey(10);

    transposeText();

    // for(i=0;i<16;i++){
    //     printf("%x ", text[i]);
    // }
}

int sendData(int new_socket, char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("File not found\n");
        exit(1);
    }

    memset(text, 0, 16);
    int dataLength;
    int endLength = 0;

    while (dataLength = fread(text, sizeof(uint8_t), 16, file) > 0) {
        int i;
        encrypt();

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

    expanded_key = keyExpansion();
    
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

