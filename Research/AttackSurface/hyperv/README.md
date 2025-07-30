# Awesome Hyper-V Exploitation [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
A curated list of Hyper-V exploitation resources, fuzzing and vulnerability research.

If you want to contribute, please read the [guide](CONTRIBUTING.md).

For a broader list of virtualization related links, see [Awesome Virtualization](https://github.com/Wenzel/awesome-virtualization).

### Table of Contents
- [Conference Talks & Slides](#talks_slides)
- [Blog Posts](#blogs)
- [References & Resources](#references_resources)
- [Security Research Tools](#security_tools)


## <a name="talks_slides" />Conference Talks & Slides
*Conference talks/slides related to vulnerabilities and exploits in Hyper-V*
+ [Hypervisor Vulnerability Research: State of the Art](https://www.youtube.com/watch?v=1bjekpgZCgU) - by Alisa Esage, Zer0Con [2020]
	- [Slides](https://alisa.sh/slides/HypervisorVulnerabilityResearch2020.pdf)
+ Attacking Hyper-V - by Jaanus Kääp, POC [2019]
	- [Slides](https://github.com/FoxHex0ne/Slides/blob/master/POC2019.pdf)
+ [Exploiting the Hyper-V IDE Emulator to Escape the Virtual Machine](https://www.youtube.com/watch?v=50xxJEODO3M) - by Joe Bialek, BlackHat USA [2019]
	- [Slides](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_08_BlackHatUSA/BHUSA19_Exploiting_the_Hyper-V_IDE_Emulator_to_Escape_the_Virtual_Machine.pdf)
+ [Growing Hypervisor 0day with Hyperseed](https://www.youtube.com/watch?v=Qms328deZ68) - by Daniel King & Shawn Denbow, OffensiveCon [2019]
	- [Slides](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_OffensiveCon/2019_02%20-%20OffensiveCon%20-%20Growing%20Hypervisor%200day%20with%20Hyperseed.pdf)
+ [Hardening Hyper-V Through Offensive Security Research](https://www.youtube.com/watch?v=8RCH0vFxWT4) - by Jordan Rabet, BlueHat [2018]
	- [Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Rabet-Hardening-Hyper-V-Through-Offensive-Security-Research.pdf)
+ [A Dive in to Hyper-V Architecture & Vulnerabilities](https://www.youtube.com/watch?v=p28eTnKo8sw) - by Joe Bialek & Nicolas Joly, TenSec [2018]
	- [Slides](https://github.com/Microsoft/MSRC-Security-Research/blob/master/presentations/2018_08_BlackHatUSA/A%20Dive%20in%20to%20Hyper-V%20Architecture%20and%20Vulnerabilities.pdf)
+ VBS and VSM Internals - by Saar Amar, BlueHat IL [2018]
	- [Slides](https://github.com/saaramar/Publications/blob/master/BluehatIL_VBS_meetup/VBS_Internals.pdf)
+ [The Hyper-V Architecture and its Memory Manager](https://recon.cx/media-archive/2017/mtl/recon2017-mtl-10-andrea-allievi-The-HyperV-Architecture-and-its-Memory-Manager.mp4) - by Andrea Allievi, REcon [2017]
+ [Ring 0 to Ring -1 Attacks - Hyper-V IPC Internals](https://www.youtube.com/watch?v=_NaRZvrs8xY) - by Alex Ionescu, SyScan [2015]
	- [Slides](http://www.alex-ionescu.com/syscan2015.pdf)

## <a name="blogs" />Blog Posts
*Security research blog posts for learning how to find vulnerabilities/exploit Hyper-V*

+ [First Steps in Hyper-V Research](https://msrc-blog.microsoft.com/2018/12/10/first-steps-in-hyper-v-research/) - by Saar Amar, MSRC Blog [2018]
+ [Fuzzing para-virtualized devices in Hyper-V](https://msrc-blog.microsoft.com/2019/01/28/fuzzing-para-virtualized-devices-in-hyper-v/) - by Secure Windows Initiative Attack Team, MSRC Blog [2019]
+ [Attacking the VM Worker Process](https://msrc-blog.microsoft.com/2019/09/11/attacking-the-vm-worker-process/) - by Saar Amar, MSRC Blog [2019]
+ [Ventures into Hyper-V - Fuzzing hypercalls](https://labs.mwrinfosecurity.com/blog/ventures-into-hyper-v-part-1-fuzzing-hypercalls) - by Amardeep Chana, MWR Labs [2019]
+ [Writing a Hyper-V "Bridge" for Fuzzing -- Part 1: WDF](http://www.alex-ionescu.com/?p=377) - by Alex Ionescu [2019]
+ [Writing a Hyper-V "Bridge" for Fuzzing -- Part 2: Hypercalls & MDLs](http://www.alex-ionescu.com/?p=471) - by Alex Ionescu [2019]

## <a name="references_resources" />References & Resources
*Useful Hyper-V research references and resources*

+ [Microsoft Hyper-V Bounty Program](https://www.microsoft.com/en-us/msrc/bounty-hyper-v) - by Microsoft
+ [Hyper-V symbols for debugging](https://techcommunity.microsoft.com/t5/Virtualization/Hyper-V-symbols-for-debugging/ba-p/382416) - by Microsoft
+ [Hyper-V Internals](https://hvinternals.blogspot.com/) - by Gerhart
+ [Hyper-V Architecture](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/hyper-v-architecture) by Microsoft Docs
+ [Hyper-V Hypervisor Top-Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs) - by Microsoft Docs
+ [Install Hyper-V on Windows 10](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v) - by Microsoft Docs
+ [Create Virtual Machine with Hyper-V on Windows](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/create-virtual-machine) - by Microsoft Docs
+ [Run Hyper-V In a Virtual Machine with Nested Virtualization](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization) - by Microsoft Docs

## <a name="security_tools" />Security Research Tools
*Tools for doing security research and introspection on Hyper-V*

+ [hdk -- (unofficial) Hyper-V Development Kit](https://github.com/ionescu007/hdk) - by Alex Ionescu
+ [Viridian Fuzzer -- Kernel driver to fuzz Hyper-V hypercalls](https://github.com/mwrlabs/ViridianFuzzer) - by Amardeep Chana, MWR Labs
+ [LiveCloudKd](https://github.com/comaeio/LiveCloudKd) - by Matt Suiche, Comae Technologies
+ [HyperViper -- Toolkit for Hyper-V security research](https://github.com/FoxHex0ne/HyperViper) - by Jaanus Kääp, Clarified Security
