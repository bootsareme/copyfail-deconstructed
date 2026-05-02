CC = gcc

CFLAGS = -g -O2 -Wall -Wextra -pedantic -fsanitize=address
LDFLAGS = -g -Wall -Wextra -O2 -fsanitize=address
EXEC = c_infect_copyfail.exe
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(EXEC) payload

%.o: %.c %.h
	gcc -o $@ -c $< $(CFLAGS)

payload:
	gcc -c ../payloads/shellcode_x64.S
	objcopy -O binary shellcode_x64.o payload_x64.raw
	xxd -i payload_x64.raw > payload.txt

$(EXEC): $(OBJECTS)
	gcc -o $@ $< $(LDFLAGS)

clean:
	-rm *.o
	-rm $(EXEC)



