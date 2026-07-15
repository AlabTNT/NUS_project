# Project Dossier: Low-Level NFC Attack & Defense System

## 1. Project Overview & Meta-Data
* **Course/Context:** NUS Computer Security Project (21-Day Agile Timeline).
* **Core Objective:** Pivot from generic kernel/OS/hardware security to lower-level NFC (13.56MHz) vulnerability exploitation (Protocol Relay/MITM/Logic Bypass) and design a functional hardware-level/physical-layer academic defense mechanism.
* **Core Philosophy:** Avoid the time sink of custom PCB fabrication and antenna impedance tuning by leveraging existing hardware ecosystems, focusing purely on low-level firmware, protocol state machines, and RF signal processing.

---

## 2. Team Composition & Skill Matrix
* **CS/IS Students (2 members, including User):** * *Skills:* Completed the "Hardware-Software Integrated Course" (计算机软硬件贯通课). Deep understanding of computer systems, microcontrollers (C/C++), firmware debugging, and information security principles.
    * *Role:* Firmware exploitation, protocol stack reversing, logic bypass execution, and defensive FSM (Finite State Machine) coding.
* **EE Students (2 members):**
    * *Skills:* No computer systems integration background, but strong foundation in *Signals and Systems* and telecommunications.
    * *Role:* Physical-layer RF signal analysis, ASK/load modulation wave decoding, RTT (Round Trip Time) physical analysis, and active RF jamming implementation.

---

## 3. Approved Hardware Assets (The Sandbox)
1.  **Proxmark3 RDV (Legacy Model):** * *Role:* Protocol sniffing, raw frame injection, and hardware card emulation. 
    * *Constraint:* Older MCU with limited Flash (typically 256KB/512KB). Requires custom, stripped-down firmware compilation.
2.  **HackRF One:** * *Role:* Software Defined Radio (SDR) for 13.56MHz I/Q signal capturing, physical-layer wave analysis, and active RF jamming (Defense).
3.  **Assorted Tag Pool:** * *Role:* Mix of standard ISO/IEC 14443A (M1/CPU) cards and unknown Magic Cards (UID changeable Gen1a/CUID) that need sorting.

---

## 4. Software & Firmware Stack
* **Firmware Repository:** [RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3) (The Iceman Community Fork).
* **Compilation Strategy:** * CS/IS team configures `Makefile.platform` to optimize for legacy hardware (`PLATFORM=PM3RDV2` or `PM3GENERIC`, `PLATFORM_SIZE=256`).
    * Strip out all Low Frequency (LF) components to fit the 13.56MHz constraints.
* **Distribution Workflow:** CS/IS flashes the PM3 hardware -> Bundles compiled client binaries (`pm3.exe`), Windows `.inf` drivers, and an automated `.bat` startup script -> Distributes pre-flashed hardware and client folders to EE students to abstract environment setup.
* **Signal Analysis & RF Defense Environment:** GNU Radio, MATLAB, or Python for I/Q sample processing.

---

## 5. 21-Day Sprint & Experimental Syllabus

### Phase 1: Diagnostics & Hardware Provisioning (Days 1–3)
* **Task 1 (CS/IS):** Flash and strip the Iceman firmware; establish the unified client environment.
* **Task 2 (EE/All):** Tag Classification Sandbox. Execute `hf search` and `hf mf cdetect` on the PM3 client to isolate Gen1a Magic Cards by testing command backdoors (`0x43`/`0x40`) and verifying UID mutations via `hf mf csetuid`.

### Phase 2: Vulnerability Exploitation (Days 4–14)
* **Milestone 1: Logic Bypass (CS/IS):** Execute `hf mf sniff` and `hf list 14443a` to audit targeted readers. Identify setups verifying only the UID without subsequent sector cryptographic challenges. Clone targeted UIDs to identified Magic Cards to achieve physical bypass.
* **Milestone 2: Physical Layer Profiling (EE):** Capture 13.56MHz card-reader transactions using HackRF One (20Msps sample rate). Demodulate 100%/10% ASK reader commands and subcarrier load-modulation responses. Calculate precise Frame Delay Times (FDT) in microseconds ($\mu s$) to gauge network relay latency thresholds.

### Phase 3: Academic Defense System (Days 15–19)
* **Concept: Active Link Fuse / Reactive Jammer**
    * **Mechanism:** Using GNU Radio + HackRF One to dynamically monitor the 13.56MHz spectrum during transactions.
    * **Action:** If anomalous physical characteristics (e.g., multi-path attenuation indicating proxy hardware) or prolonged transmission delays (Relay Attack) are detected, HackRF immediately triggers a short, high-energy 13.56MHz noise burst.
    * **Result:** Intentionally breaks RF synchronization, causing the attacking Proxmark3 to throw a `Missing Sync` error, successfully mitigating the threat.

### Phase 4: Live Demo Presentation (Days 20–21)
* **Demo A (Attack):** Showcasing logic vulnerability by opening a test rig with a cloned Magic Card.
* **Demo B (Defense):** Activating the HackRF defense grid; re-attempting the attack, showing real-time spectrum disruption in GNU Radio, and verifying the attack fails gracefully.
