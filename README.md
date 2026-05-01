# copyfail-deconstructed
Easy to understand version of [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431). The original proof-of-concept is found here: https://github.com/theori-io/copy-fail-CVE-2026-31431, but is heavily compressed and minified so it can have as small of a footprint as possible. This repository attempts to break down that code in a more readable manner, including what the code does, how the payload is loaded, and how to target different platforms. See the more technical writeup here: https://xint.io/blog/copy-fail-linux-distributions.

## Usage
Simply run `python3 copyfail.py [path/to/payload.elf]` and it will inject said payload into `/usr/bin/su`. To get `payload.elf` in the first place, assemble and link:
```
to be continued...
```
## Fixes
