CC = gcc

CFLAGS = -g -O2 -Wall -Wextra -pedantic
LDFLAGS = -g -Wall -Wextra -O2
EXEC = c_copyfail
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(EXEC).exe $(EXEC)-32.exe payload_x86-64 payload_x86-32

%.o: %.c %.h
	gcc -o $@ -c $< $(CFLAGS)

payload_x86-64:
	gcc -c ../payloads/shellcode_x86-64.S
	objcopy -O binary shellcode_x86-64.o payload_x86-64.raw
	xxd -i payload_x86-64.raw > payload_x86-64.txt

payload_x86-32:
	gcc -m32 -c ../payloads/shellcode_x86-32.S
	objcopy -O binary shellcode_x86-32.o payload_x86-32.raw
	xxd -i payload_x86-32.raw > payload_x86-32.txt

$(EXEC).exe: $(OBJECTS)
	gcc -o $@ $< $(LDFLAGS)

$(EXEC)-32.exe: copyfail.c
	gcc -m32 -static -o copyfail-32.o -c $< $(CFLAGS)
	gcc -m32 -static -o $@ copyfail-32.o $(LDFLAGS)

clean:
	-rm *.o
	-rm *.exe
	-rm *.txt
	-rm *.raw
