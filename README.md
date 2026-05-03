# copyfail-deconstructed
Easy-to-understand version of [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431), a privilege escalation technique that allows anybody to become root. The original proof-of-concept is found here: https://github.com/theori-io/copy-fail-CVE-2026-31431, but is heavily compressed and minified so it can have as small of a footprint as possible. This repository attempts to break down that code in a more readable manner, including what the code does, how the payload is loaded, and how to target different architectures. See the more technical writeup here: https://xint.io/blog/copy-fail-linux-distributions.

## Usage
By default, running `python3 copyfail.py` will run x64 shellcode exploiting `/usr/bin/su`. You can supply your own payload by running `python3 copyfail.py [path/to/custom/payload.elf]`. As an example, there is an ARM64 shellcode assembly inside `payloads/`. So to test on ARM64 devices, you first should build a minimized payload with our custom linker script:

```
as -o shellcode_aarch64.o payloads/shellcode_aarch64.S
ld -nostdlib -static -o shellcode_aarch64.elf shellcode_aarch64.o
strip -s shellcode_aarch64.elf
```
Then you can run the main exploit using `python3 copyfail.py shellcode_aarch64.elf`.

For running on C:
1. build (seen below)
2. `./c_copyfail` which runs the same default shellcode as above.
  - You can again supply your own payload by running `./c_copyfail [path/to/custom/payload.elf]`.  

For building the C version:
```
cd c_port
make
```

Specifically, this compiles the target .S file into a raw binary which is output as a C unsigned char array:
```
gcc -c payloads/[shellcode].S
objcopy -O binary [shellcode].o [payload].raw
xxd -i [payload].raw > payload.txt
```
or, for 32 bit x86,
```
gcc -c -m32 payloads/[shellcode].S
objcopy -O binary [shellcode].o [payload].raw
xxd -i [payload].raw > payload.txt
```

You can then copy the contents of this file into your source code, or you can just directly run `./c_copyfail.exe [path/to/payload.elf]` where `payload.elf` is generated from `as` + `ld` NOT `gcc` + `objcopy`.

## Fixes
To avoid exploitation, run:
```
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf
rmmod algif_aead 2>/dev/null
```
If already exploited, you can restart the machine, or run:
`echo 3 | sudo tee /proc/sys/vm/drop_caches`

## Explanation
1. Kernel allows user to talk to crypto API through socket type `AF_ALG`
  - In 2017, "in-place optimisation" was added to algif_aead part of crypto API
  - When data is sent through the socket using `splice()` system call, kernel puts actual page-cache pages of the file you spliced into the crypto work area
  - Crypto algo authencsn treats its output buffer as scratch space and writes 4 bytes past where it's supposed to
2. What hypothetical party can do
  - Pick any readable file (e.g., `/usr/bin/su` in this case)
  - Choose offset inside that file where 4-byte write will happen
  - Choose 4-byte value to write (part of associated data in AEAD operation)
  - Write shell code to overwrite file in-memory
3. Page-cache overwriting to root
  - Kernel never marks corrupted page as dirty, file looks unchanged
  - When executing `/usr/bin/su`, kernel reads it from page cache and gets modified bytes
  - By repeating 4-byte write (about 40 times), they can overwrite UID check inside `/usr/bin/su` so UID is 0 (root)
  - Root shell achieved for any user
4. Remediation
  - Flush page cache to remove modified files in memory, so it will read from disk next time
  -  Unload kernel module
  -  Blacklist from loading
  -  If its a built-in module, you have to block the syscall using seccomp or eBPF. Or remove it from initializing and reboot the machine.

The `su` binary is corrupted in-memory, so file modification will not be detected. To restore from disk, you can flush the page-cache.
