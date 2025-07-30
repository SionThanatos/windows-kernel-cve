# Windows Kernel Attack Surface Research Collection

This repository is a comprehensive collection of research, analysis, and resources focused on Windows kernel security, with a special emphasis on attack surfaces. It is designed for security researchers, vulnerability analysts, and anyone interested in Windows internals and kernel exploitation.

---

## Project Overview

This project organizes and documents various attack surfaces in the Windows kernel and related components. Each attack surface is represented by a dedicated folder under `Research/AttackSurface/`, containing technical documentation, proof-of-concept code, and/or analysis. The repository also includes a large collection of CVE-specific research (see the `CVEs/` directory).

---

## Directory Structure

- [CVEs/](CVEs/)  
  Collection of Windows kernel-related CVE analyses and exploit resources. Each subdirectory corresponds to a specific CVE or group of CVEs.

- [Research/AttackSurface/](Research/AttackSurface/)  
  Main directory for attack surface research. Each subdirectory represents a different attack surface. PDF documents provide in-depth studies and presentations.



---

## Attack Surfaces

Below are the main Windows kernel attack surfaces covered in this repository. Click a folder to explore its content.

- [afd/](Research/AttackSurface/afd/)  
  Ancillary Function Driver (AFD) is responsible for Windows socket operations. Vulnerabilities here can lead to privilege escalation or remote code execution via network APIs.

- [clfs/](Research/AttackSurface/clfs/)  
  Common Log File System (CLFS) is used for transactional logging in Windows. Bugs in CLFS can allow attackers to corrupt logs or escalate privileges.

- [COM/](Research/AttackSurface/COM/)  
  Component Object Model (COM) is a core Windows technology for inter-process communication. Misuse or vulnerabilities can result in privilege escalation or code execution.

- [directx/](Research/AttackSurface/directx/)  
  DirectX handles multimedia and gaming APIs. Vulnerabilities may allow attackers to exploit graphics drivers or escalate privileges via GPU interfaces.

- [DWM/](Research/AttackSurface/DWM/)  
  Desktop Window Manager (DWM) manages desktop composition and rendering. Flaws can lead to local privilege escalation or denial of service.

- [ebpf/](Research/AttackSurface/ebpf/)  
  eBPF (extended Berkeley Packet Filter) is a programmable packet processing engine. Windows eBPF is new and may expose novel kernel attack vectors.

- [font/](Research/AttackSurface/font/)  
  The font subsystem parses and renders fonts in the kernel. Malformed fonts can trigger vulnerabilities, often leading to code execution.

- [hyperv/](Research/AttackSurface/hyperv/)  
  Hyper-V is Microsoft’s virtualization platform. Vulnerabilities can allow guest-to-host escapes or privilege escalation in virtualized environments.

- [KS/](Research/AttackSurface/KS/)  
  Kernel Streaming (KS) is used for audio and video streaming in Windows. Bugs here can be exploited for privilege escalation or information disclosure.

- [ktm/](Research/AttackSurface/ktm/)  
  Kernel Transaction Manager (KTM) manages kernel-level transactions. Vulnerabilities may allow attackers to manipulate system transactions for escalation.

- [outlook/](Research/AttackSurface/outlook/)  
  Microsoft Outlook integration with the OS can expose kernel attack surfaces, especially via file and protocol handlers.

- [printer/](Research/AttackSurface/printer/)  
  The Windows printing subsystem has a long history of vulnerabilities, including Print Spooler bugs that allow remote or local code execution.

- [rdp/](Research/AttackSurface/rdp/)  
  Remote Desktop Protocol (RDP) enables remote access to Windows systems. Vulnerabilities can lead to remote code execution or session hijacking.

- [rpc/](Research/AttackSurface/rpc/)  
  Remote Procedure Call (RPC) is widely used for inter-process and network communication. RPC bugs can be leveraged for privilege escalation or remote attacks.

- [uefi/](Research/AttackSurface/uefi/)  
  Unified Extensible Firmware Interface (UEFI) is the system firmware. Kernel-level vulnerabilities here can allow persistent and stealthy attacks.

- [Win32k/](Research/AttackSurface/Win32k/)  
  Win32k is the Windows GUI subsystem in the kernel. It is a frequent target for privilege escalation due to its large attack surface.

- [windows-defender/](Research/AttackSurface/windows-defender/)  
  Windows Defender is the built-in antivirus. Vulnerabilities can allow attackers to bypass protections or escalate privileges.

- [wmi/](Research/AttackSurface/wmi/)  
  Windows Management Instrumentation (WMI) provides management data and operations. WMI bugs can be abused for persistence or privilege escalation.

- [wsl/](Research/AttackSurface/wsl/)  
  Windows Subsystem for Linux (WSL) allows running Linux binaries on Windows. Vulnerabilities may allow crossing the Windows/Linux boundary for attacks.

---

## Research and References

The following documents in `Research/AttackSurface/` provide in-depth studies and overviews of Windows kernel attack surfaces:



## License

This repository is for educational and research purposes only. Please use responsibly.
