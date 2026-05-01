# copyfail-deconstructed
Easy to understand version of [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431). The original proof-of-concept is found here: https://github.com/theori-io/copy-fail-CVE-2026-31431, but is heavily compressed and minified so it can have as small of a footprint as possible. This repository attempts to break down that code in a more readable manner, including what the code does, how the payload is loaded, and how to target different platforms. See the more technical writeup here: https://xint.io/blog/copy-fail-linux-distributions.

## Usage
Simply run `python3 copyfail.py [path/to/payload.elf]` and it will inject said payload into `/usr/bin/su`. To get `payload.elf` in the first place, assemble and link:
```
to be continued...
```
## Fixes
To avoid exploitation, run:
```
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf
rmmod algif_aead 2>/dev/null
```
If already exploited, you can restart the machine, or run:
`echo 3 | sudo tee /proc/sys/vm/drop_caches`

## Explanation
1. Kernel allows user to talk to crypto API through socket type AF_AFL
  - In 2017, "in-place optimisation" was added to algif_aead part of crypto API
  - When data is sent through the socket using splice() system call, kernel puts actual page-cache pages of the file you spliced into the crypto work area
  - Crypto algo authencsn treats its output buffer as scratch space and writes 4 bytes past where it's supposed to
2. What hypothetical party can do
  - Pick any readable file (e.g., /usr/bin/su in this case)
  - Choose offset inside that file where 4-byte write will happen
  - Choose 4-byte value to write (part of associated data in AEAD operation)
  - Write shell code to overwrite file in-memory
3. Page-cache overwriting to root
  - Kernel never marks corrupted page as dirty, file looks unchanged
  - When executing /usr/bin/su, kernel reads it from page cache and gets modified bytes
  - By repeating 4-byte write (about 40 times), they can overwrite UID check inside /usr/bin/su so UID is 0 (root)
  - Root shell achieved for any user
4. Remediation
  - Flush page cache to remove modified files in memory, so it will read from disk next time
  -  Unload kernel module
  -  Blacklist from loading
  -  If its a built-in module, you have to block the syscall using seccomp or eBPF. Or remove it from initializing and reboot the machine.

The 'su' binary is corrupted in-memory, so file modification will not be detected. To restore from disk, you can flush the page-cache.
