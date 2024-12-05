# CVE-2023-36407

This is poc for CVE-2023-36407, Hyper-V Elevation of Privilege Vulnerability.

https://github.com/pwndorei/CVE-2023-36407/assets/96749184/a8ef87d3-e0d0-40e5-9b23-35ab057a9c78

## Vulnerability

- OOB Read/Write from/to Non-paged Pool via `winhvr.sys!WinHvGet/SetVpState`

# Reproduction Steps

- Environment I used: Windows 11 22H2 x64
- Patch: kb5031354
- control code for `WinHvSetVpState`: 0x221268
    - if poc does not work, analyze `Vid.sys` to find out control code for `WinHvSetVpState` and change it

## Build

Just build the project(Release/x64), then `CVE-2023-36407.exe` will be generated.

## Reproduction

1. run `CVE-2023-36407.exe` in vulnerable Hyper-V Host(Root Partition)
2. **Boom**

### How it works?

1. `CVE-2023-36407.exe` calls `DeviceIoControl` that invokes `winhvr.sys!WinHvSetVpState`
2. In `WinHvSetVpState`, `memcpy` copies data from input buffer(user-controlled) to Non-paged Pool memory
    - length of data to copy depends on input data's length
3. The Non-paged Pool Memory is 0x1000 bytes size and there is no size check for input before calling `memcpy`
    - BOF in Non-paged Pool
4. BSOD occurs because of the corruption
