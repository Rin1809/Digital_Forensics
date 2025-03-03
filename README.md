<details>

<summary><h1>This repository, i just want to show what Digital Forensics work (doing realistic simulation lab ). If care about it so span it down ᓚᘏᗢ </h1></summary>

# Digital_Forensics

![image](https://github.com/user-attachments/assets/da81535d-c9e2-4d72-a2eb-6c07bf2e6f52)

This repository documents a series of digital forensics exercises performed in a simulated lab environment.  Each task demonstrates a key aspect of a digital forensics investigation, from image acquisition to memory analysis.

# Task 1: Create a DD-format Image File

**Objective:** Create a bit-by-bit copy (a "forensic image") of a drive using the `dd` command, a standard tool in Linux for low-level data copying.  This is a fundamental first step in many investigations, as it allows you to work on a copy of the evidence without altering the original.

![image](https://github.com/user-attachments/assets/9ac2fee2-7629-457e-9d5f-1287ce2ff783)

*   **Step 1: File and Group Permissions (Linux)**
    *   Before creating the image, we set up appropriate permissions.  This is good practice to ensure that only authorized users can access the sensitive data within the image file.
    *   We create a group, add the group to the file (which will be created later), assign ownership, and set access rights.  This limits who can read, write, and execute the image file.

    ![image](https://github.com/user-attachments/assets/f5dc2132-9029-4bf8-b62e-4319ee676c9f)

*   **Step 2: Samba Configuration (Network Share)**
    *   Samba is used to create a network share, allowing us to access the image file (and other files) from different machines. This is useful for collaboration or if your analysis tools are on a different system than where the image is created.
    *   We create a user, set a Samba password for that user, and add the user to a dedicated group (`nhomdieutra`, meaning "investigation group").

    ![image](https://github.com/user-attachments/assets/40a3a8a3-ad95-4c89-8518-18d7507082f4)

*   **Step 3: Initial Mapping (Physical Machine)**
    *   We first attempted to map a network drive from a Kali Linux machine (a common distribution used for penetration testing and digital forensics) to the physical machine where the target drive was located.

    ![image](https://github.com/user-attachments/assets/f14ae1e3-56f4-4311-af25-b37ef9986e15)

*   **Step 4: Switch to Virtual Machine**
    *   Due to the large size of the target drive (500GB), we switched to using a virtual machine.  This avoids transferring a massive amount of data over the network.

    ![image](https://github.com/user-attachments/assets/fb2add65-4fda-4c7e-97d5-ba04d6300053)

*   **Step 5: Mapping to Virtual Machine**
    *   We successfully mapped a network drive to the virtual machine.

    ![image](https://github.com/user-attachments/assets/9e370bd2-53ef-4cfe-87b5-a71f06c290e8)

*   **Step 6: Identify Target Drive**
    *   We identified the target drive as "Drive E".  This is the drive we want to image. *Crucially*, we made sure that this was the correct drive before proceeding, to avoid accidentally imaging the wrong data.

    ![image](https://github.com/user-attachments/assets/b9e04084-3d47-46d9-97f8-f0004c72928d)

*   **Step 7: Image Acquisition (dd)**
    *   We used the `dd` command (likely with appropriate parameters like `if=/dev/sdb` (input file - the source drive), `of=/path/to/image.dd` (output file - the destination image), `bs=4k` (block size), and `conv=noerror,sync` (to handle read errors)) to create the `dd` image.  The exact `dd` command used *should be documented here*.  This is the core of the task.

    ![image](https://github.com/user-attachments/assets/d656eba5-dbd2-4d8b-80e2-ece70e4931df)

*   **Step 8: Verification (Kali Linux)**
    *   We checked the Kali Linux machine to confirm the image creation.

    ![image](https://github.com/user-attachments/assets/e2dc0d45-1e38-4fb8-b925-f24515a7ea3c)

*   **Step 9: Integrity Check (MD5 Hash)**
    *   We calculated the MD5 hash of the newly created image file.  This is *critical* for ensuring data integrity.  The MD5 hash acts as a digital fingerprint of the image.  If even a single bit changes, the MD5 hash will be completely different.  We will use this hash later to verify that the image hasn't been altered during analysis.

    ![image](https://github.com/user-attachments/assets/3102fae5-3190-4470-8d7e-30a8733edc74)

# Task 2: Convert the Image File from E01 to DD Format

**Objective:** Convert a forensic image from the EnCase Evidence File format (E01) to the raw `dd` format.  E01 is a proprietary format commonly used by EnCase software.  Converting to `dd` makes the image compatible with a wider range of open-source tools.

*   **Step 1: Transfer E01 File**
    *   We copied the `Windows_001.E01` file to the mapped network drive accessible from the Kali Linux machine.

    ![image](https://github.com/user-attachments/assets/d7115474-e47a-4cb7-a6df-e4c8994cd6c2)

*   **Step 2: Conversion with `xmount`**
    *   We used the `xmount` utility to convert the E01 file to the `dd` format.  `xmount` can also create a virtual drive from the image, allowing us to mount it. The likely command used was something like:  `xmount --in ewf --out dd Windows_001.E01 /mnt/e01_mount` (where `/mnt/e01_mount` is a directory you create beforehand).  The `--in ewf` specifies the input format as EnCase (EWF), and `--out dd` specifies the output as raw `dd`.

    ![image](https://github.com/user-attachments/assets/f37c4d3b-473a-4f40-9931-94563d54f090)

# Task 3: Mount the Image File on a Linux Workstation

**Objective:** Mount the `dd` image file as a read-only filesystem to access its contents.  Mounting allows us to browse the files and directories within the image as if it were a regular drive.

*   **Step 1: Examine Mounted Files**
    *   We checked the contents of the mounted directory (`/mnt/dd`) to verify that the image was mounted correctly and to begin exploring the filesystem.

    ![image](https://github.com/user-attachments/assets/8cbf9276-9bd9-4589-bec8-6ef808223639)
    ![image](https://github.com/user-attachments/assets/53ef2679-1f02-4fb9-b557-b54df49a78cf)
    ![image](https://github.com/user-attachments/assets/603529df-5f00-4e48-8ed3-b607175e183a)

*   **Step 2: MD5 Hashing (Images Directory)**
    *   We calculated the MD5 hashes of files within the `/mnt/dd/images` directory and saved the results to `yeucaubailab.txt`.  This is an example of extracting information from the mounted image.  The specific command used was likely something like: `find /mnt/dd/images -type f -print0 | xargs -0 md5sum > yeucaubailab.txt`. This finds all regular files (`-type f`) in the directory, prints their names separated by null characters (`-print0`), and then uses `xargs -0` to pass those filenames to `md5sum`, safely handling filenames with spaces or special characters.

    ![image](https://github.com/user-attachments/assets/a88ecb29-90af-4da0-9d86-91fc4a3e2eb7)
    ![image](https://github.com/user-attachments/assets/ecbe52ef-9a93-4d37-b2e0-5e0acf40fc58)

*   **Step 3: MD5 Hashing (Songs Directory)**
    *   We repeated the MD5 hashing process for files in the "Songs" directory. This demonstrates how to extract data from different parts of the image.

    ![image](https://github.com/user-attachments/assets/656a2f4d-c805-4a15-a4b0-fe1e144e4be9)

*   **Step 4: Mounting an APFS Image**
    *   We mounted another `dd` image file, this one containing an Apple File System (APFS). This demonstrates working with different file system types. The likely command would have been something like:  `sudo mount -t apfs -o ro,loop /path/to/image.dd /mnt/apfs` (where `/mnt/apfs` is a mount point you create beforehand).  The `-t apfs` specifies the filesystem type, `-o ro,loop` mounts it read-only and uses the loop device.

    ![image](https://github.com/user-attachments/assets/4e46772b-c242-424f-8853-73d9af7e9948)

*   **Step 5: MD5 Hashing (.fseventsd)**
    *   We calculated the MD5 hash of the `.fseventsd` directory (and likely its contents).  `.fseventsd` is a directory used by macOS to store file system events. Analyzing this can provide information about file creation, modification, and deletion.

    ![image](https://github.com/user-attachments/assets/34056b0c-840f-443b-90ad-b622278c7ed0)
    ![image](https://github.com/user-attachments/assets/97d5345e-a02a-4545-8499-223868d0a24f)

*   **Step 6: Continued Hashing**
    *   We continued calculating hashes and saving them to a text file, likely for further analysis or reporting.

    ![image](https://github.com/user-attachments/assets/0d503e45-7bfe-4698-b432-7adaf70c0a19)

*   **Step 7: Results**
    *   Displayed the results of the hashing operations.

    ![image](https://github.com/user-attachments/assets/2083c720-35a9-4159-b162-4996486d0f99)

# Task 4: Extract Hidden Content from the Hard Drive

**Objective:** Use Python scripts to analyze the image and potentially extract hidden content.  This task likely involves parsing file system structures to find deleted files, unallocated space, or other areas where data might be concealed.

*   **Script 1: `Phan_tich_Image.py` (Image_Analysis.py)**
    *   This script likely performs initial analysis of the image.  Without the script code, it's impossible to say exactly what it does, but common tasks include parsing the Master File Table (MFT) in NTFS, identifying file entries, and potentially recovering deleted files.

    ![image](https://github.com/user-attachments/assets/059545f4-ead6-4089-90ef-7c5405166da6)

*   **Script 2: `phan_tich_image_pro.py` (Image_Analysis_Pro.py)**
    *   This script likely builds upon the first script, adding more advanced features or analysis capabilities. This might involve more in-depth parsing of file system structures, searching for specific file types, or attempting to reconstruct fragmented files.

    ![image](https://github.com/user-attachments/assets/106c14e8-a4a7-4f37-9601-e00a7e5a5a6c)
    ![image](https://github.com/user-attachments/assets/63d7b60c-28cc-4333-b029-fcd292809a50)

*   **User Directory Exploration**
    *   We browsed the home directory of the user "roger," specifically navigating to the "Downloads" directory.  This suggests a targeted search for potentially relevant files.

    ![image](https://github.com/user-attachments/assets/6635d2c1-7026-4636-864b-2a423f3e0664)

*   **Script 3: `phan_tich_image_pro_max.py` (Image_Analysis_Pro_Max.py)**
    *   This script likely represents the most advanced version of the analysis tool, potentially incorporating features like web server integration for easier access to results.

    ![image](https://github.com/user-attachments/assets/5eb9c477-a010-4fdc-a3e7-28a8164d465f)

*   **Web Server Access (host='0.0.0.0')**
    *   The addition of `host='0.0.0.0'` in the script suggests that a web server was started.  Setting the host to `0.0.0.0` makes the server accessible from any network interface on the machine, allowing access from other computers (like the physical machine).

    ![image](https://github.com/user-attachments/assets/7fadfc17-8f71-4031-a182-12a313c9644f)
    ![image](https://github.com/user-attachments/assets/6e114bb2-fe2f-4a6e-ac6a-c4a2dd0eb345)

# Task 5: Analyze the Windows Image File System

**Objective:** Use The Sleuth Kit (TSK) tools (`mmls` and `fsstat`) to examine the low-level structure of the file system within the `Windows_002.dd` image.

*   **Step 1: Partition Table Analysis (`mmls`)**
    *   We used the `mmls` command to display the partition table of the `Windows_002.dd` image.  This shows how the disk is divided into partitions, including their starting and ending sectors, sizes, and types. This command helps understand the disk layout *before* looking at the file system itself.  Example: `mmls Windows_002.dd`.

    ![image](https://github.com/user-attachments/assets/1684fac8-6405-4523-8b06-6bea83689b9f)

*   **Step 2: File System Details (`fsstat`)**
    *   We used the `fsstat` command to display detailed information about the file system, including the file system type (e.g., NTFS, FAT32), volume label, block size, and other metadata. Example: `fsstat Windows_002.dd`.

    ![image](https://github.com/user-attachments/assets/c9a15a7b-3710-433a-86fb-11bd4bae75bd)

*   **NTFS Metadata Entries:**
    *   The following are key metadata entries within the NTFS file system:

        *   **5: Root Directory:**  The top-level directory of the file system.  All other files and directories are located within the root directory.

            ![image](https://github.com/user-attachments/assets/7fd3144f-78cc-4713-92e6-ab5c8f9d0aed)

        *   **6: Volume Bitmap:** A file that tracks which clusters (allocation units) on the volume are in use and which are free.

            ![image](https://github.com/user-attachments/assets/ef402b42-d095-4b97-a1e2-85c3c97fa6ed)

        *   **9: $Secure:**  Contains security descriptors for files and directories.  This includes Access Control Lists (ACLs) that define permissions for users and groups.

            ![image](https://github.com/user-attachments/assets/2f72d569-cfde-4e52-9c21-e36f59b4766e)

        *   **11: $Extend:**  A directory that contains other metadata files used to extend the functionality of NTFS, such as `$Quota`, `$ObjId`, and `$Reparse`.

            ![image](https://github.com/user-attachments/assets/646ea15d-fb57-43ac-8439-cc38d315a814)

* **Inode Lookup**
    * Find the file name or folder based on the inode number.
    
    ![image](https://github.com/user-attachments/assets/8015aa79-57a9-4543-bc30-861205008ea2)

*   **File Recovery**
    *   We recovered files from the image file.  This likely involved using TSK tools like `icat` (to extract the contents of a file based on its inode number) or other file carving utilities.

    ![image](https://github.com/user-attachments/assets/984c2c15-37f9-47d5-9e5c-5a40aeae5889)

# Task 6: Create and Analyze a File System Timeline using The Sleuth Kit (TSK)

**Objective:** Create a timeline of file system activity using TSK's `fls` and `mactime` tools.  Timelines are crucial in investigations to understand the sequence of events and identify suspicious activity.

*   **Step 1: Extract Temporal Data (`fls`)**
    *   We used the `fls` command to extract file system metadata, including timestamps (MAC times - Modification, Access, Change), and write the output to `ado.txt`.  `fls` lists files and directories, including deleted entries, from a disk image. A likely command would be: `fls -r -m "/" -p Windows_002.dd > ado.txt` (The `-r` is for recursive, `-m "/"` prepends the mount point, and `-p` displays full paths).

    ![image](https://github.com/user-attachments/assets/1437e3db-5915-4b45-a71b-932cb12b065c)
    ![image](https://github.com/user-attachments/assets/a8344012-f94b-40eb-a6fb-c490f165ca10)
    ![image](https://github.com/user-attachments/assets/c70ec20c-4f15-4e9c-b090-22b1fcb86f26)

*   **Step 2: Create Timeline (`mactime`)**
    *   We used the `mactime` command to process the output from `fls` (`ado.txt`) and create a chronological timeline of file system events, saving it to `task4_timeline.txt`.  `mactime` takes the output of `fls` and formats it into a human-readable timeline. Example: `mactime -b ado.txt -d > task4_timeline.txt` (the `-b` specifies the body file created by fls).

    ![image](https://github.com/user-attachments/assets/83587142-b8d2-4937-9243-d461d52cccb6)

*   **Step 3: Timeline Analysis**
    *   We analyzed the timeline to understand the sequence of events.  The timeline shows the initial creation of NTFS metadata files and directories, followed by access and modification events.  The consistent initial timestamps (Thu Dec 19 2019 16:55:24) suggest a system creation or restoration event. Later timestamps indicate activity within specific directories.

    ![image](https://github.com/user-attachments/assets/2cf933d3-7885-46f3-91f5-27ba3984a42c)

# Task 7: Analyze Common File Formats using a Hex Editor

**Objective:** Examine the internal structure of files using a hex editor.  This allows us to view the raw bytes of a file, which can reveal information not visible in a standard file viewer, such as file headers, embedded data, or signs of tampering.

*   **Step 1: Analyze "FileMau.docx" (SampleFile.docx)**
    *   We examined a DOCX file in a hex editor.  DOCX files are actually ZIP archives containing XML files.  A hex editor would allow you to see the "PK" signature at the beginning of the file, indicating a ZIP archive.

    ![image](https://github.com/user-attachments/assets/1c14c739-3336-4201-8642-1c1fae2126f9)

*   **Step 2: Analyze "FileMau.gif" (SampleFile.gif)**
    *   We examined a GIF file in a hex editor.  GIF files have a specific header ("GIF87a" or "GIF89a") that can be identified in the hex editor.  This confirms the file type and can help detect file type masquerading (where a file has been renamed with a different extension to hide its true nature).

    ![image](https://github.com/user-attachments/assets/01f5f036-697a-44f0-8b05-8543d825b0a8)

# Task 8: Collect Volatile Information from a Live Windows System

**Objective:** Use the PsTools suite to gather information from a running Windows system.  Volatile information (like running processes, network connections, and open files) is lost when the system is powered off, so it's important to collect it from a live system.

*   **PsTools Overview:**
    *   PsTools is a collection of command-line utilities from Microsoft Sysinternals that are invaluable for system administration and troubleshooting. Many of these tools are also extremely useful in incident response and digital forensics.

    ![image](https://github.com/user-attachments/assets/c77ae841-b488-4c30-a378-23a1e2976cab)

*   **1. PsKill:**
    *   Terminates a running process.  This can be useful in incident response to stop malicious processes.

    ![image](https://github.com/user-attachments/assets/f18dbc40-d2f4-4aa9-a4d7-eaab00e738d8)

    *   Example:  `.\\pskill -t 7388` (kills process with PID 7388)

*   **2. PsList:**
    *   Lists running processes, similar to Task Manager but with more detailed information.  It can show process IDs, memory usage, threads, and more.

    ![image](https://github.com/user-attachments/assets/d5657972-0698-4d95-b61c-3f4a83a92d49)

    *   Example:  `.\\PsList -x` (shows extended information)

*   **3. PsLogList:**
    *   Dumps the contents of event logs.  Event logs record system events, security audits, and application errors.  Analyzing event logs is a critical part of many investigations.

    ![image](https://github.com/user-attachments/assets/8e1e539a-d425-4623-add6-aa224baf9aef)

    *   Example:  `.\\PsLogList`

*   **4. PsPing:**
    *   Performs network connectivity tests, similar to the standard `ping` utility, but with added capabilities like measuring latency and bandwidth, and testing TCP port connectivity.

    ![image](https://github.com/user-attachments/assets/01e6420f-4b6d-4e5e-ace2-a7b573c776f3)

# Task 9: Analyze a Windows RAM Image File

**Objective:** Analyze a memory dump (RAM image) from a Windows system using Redline and Volatility.  RAM analysis is crucial for finding evidence of running malware, injected code, and other volatile data that wouldn't be present on the hard drive.

*   **Redline Analysis:**
    *   Redline is a free memory analysis tool from FireEye/Mandiant. It provides a user-friendly interface for examining various aspects of a memory dump.

    *   **1. Driver Modules:**
        *   Lists loaded device drivers.  Malware often uses kernel-mode drivers to gain deep system access and persistence.  Unusual or unknown drivers are a red flag.
        *   **Observation:**  `RamCaptureDriver64.SYS` in the Administrator's Downloads folder is *highly* suspicious. This suggests a tool used for memory acquisition, potentially by an attacker.

        ![image](https://github.com/user-attachments/assets/b95d613e-844d-47e1-a750-4da7c6533d7d)

    *   **2. Handles:**
        *   Handles are references to system resources (files, registry keys, etc.). Analyzing handles can reveal what files a process is accessing, what registry keys it's modifying, and what network connections it has open.
        *   **Example:** The provided examples show handles to registry keys related to recently run programs (`RunMRU`) and autorun programs (`Run`), both common locations for malware to establish persistence.

        ![image](https://github.com/user-attachments/assets/2a293d7f-23a9-41ce-a6c7-e75f40d8c2eb)
        ![image](https://github.com/user-attachments/assets/cd8ae2a0-e86d-4484-8a2c-0eae495ec03d)
        ![image](https://github.com/user-attachments/assets/c0a69fdc-7a3b-484f-8f91-b864ebef8aee)

    *   **3. Memory Sections:**
        *   Memory sections show the different regions of memory used by a process.  This can reveal loaded DLLs, heap allocations, and other information about the process's internal structure.  Analyzing memory sections can help identify injected code or unusual memory usage patterns.
        *   **Observation:** The analysis of `spoolsv.exe` (a print spooler service) shows that it has been compromised, leading to the creation of other processes. This is a classic example of process injection, a common malware technique.
          
           ![image](https://github.com/user-attachments/assets/949ad7d1-85b2-4e1d-9ddc-1d8db41c0077)
           ![image](https://github.com/user-attachments/assets/dc9ad625-4155-4548-88d3-0a934a212b28)

    *   **4. Device Tree:**
        *   Shows the hierarchical relationship of devices connected to the system.  This can help identify hidden or unauthorized devices, which might be used for malicious purposes (e.g., a hidden USB device).

        ![image](https://github.com/user-attachments/assets/ac4c4741-7ad7-428a-b02e-2c3d5fb02691)

    *   **5. Hooks:**
        *   Hooks are mechanisms that allow a program to intercept and modify the behavior of other programs or the operating system itself. Malware often uses hooks to hide its presence, redirect system calls, or steal data.

        ![image](https://github.com/user-attachments/assets/d909c35c-77f4-461b-be90-612b5e1d75b4)

*   **Volatility Framework:**
    *   Volatility is a powerful, open-source memory analysis framework. It provides a wide range of plugins for extracting information from memory dumps.

    *   **1. `memdump`:**
        *   Extracts the memory space of a specific process.  This is useful for isolating a suspicious process for further analysis.
        *   Command Example: `volatility_2.6_win64_standalone.exe -f "E:\\Dieu_tra_so\\Lab4-Resource\\Windows_RAM.mem" --profile=Win2008R2SP0x64 memdump -p 1896 -D "E:\\Dieu_tra_so\\Lab4-Resource\\task2"` (dumps process 1896)

         ![image](https://github.com/user-attachments/assets/2889a1a2-a34c-4cb9-86cb-f45fbf4813b9)
         ![image](https://github.com/user-attachments/assets/bef104e5-074c-4e5e-adee-2c5bd41e1a31)

    *   **2. `cmdline`:**
        *   Shows the command line used to launch each process. This can reveal how a process was started, including any command-line arguments, which can be useful for identifying suspicious activity.

        ![image](https://github.com/user-attachments/assets/e83df515-8c82-4358-a3e7-7005c6f2b656)

    *   **3. `filescan`:**
        *   Scans memory for file objects. This can find files that were open in memory, even if they have been deleted from the file system.

         ![image](https://github.com/user-attachments/assets/eb91fb12-f72d-4010-8025-dae7ba79d94f)

    * **4. driverscan**
    *    Scans for loaded drivers, and can also reveal hidden drivers.

    ![image](https://github.com/user-attachments/assets/9b1a0cc2-f239-4ac0-b17a-69c337adb4b8)

*   **`strings` Command Analysis:**
    *   The `strings` command extracts printable strings from a binary file (like a memory dump). This is a basic but useful technique for finding human-readable text within the memory image.
    *   **1. Extract Domain Names:**
        *    `strings Windows_RAM.mem | grep -E '\\.(com|net|org)' | sort | uniq`
          This extracts strings that look like domain names ending in .com, .net, or .org.

            ![image](https://github.com/user-attachments/assets/4ddf48d8-64ac-4d38-953d-b91bebee70c6)
            ![image](https://github.com/user-attachments/assets/a9dfc65c-5d92-44b5-8c34-989afe0dce51)
            ![image](https://github.com/user-attachments/assets/92648d62-df08-4edc-9090-55eca2ad1391)

    *   **2. Extract Email Addresses:**
        *   `strings Windows_RAM.mem | grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' | sort | uniq`
          This extracts strings that match the general pattern of email addresses.
          
            ![image](https://github.com/user-attachments/assets/a1cbd257-11b1-448f-a20f-c08194585ebd)

    *   **3. List Commands (cmd and PowerShell):**
        *   `strings Windows_RAM.mem | grep -i "cmd.exe " | sort | uniq` (finds command lines involving `cmd.exe`)
        *   `strings Windows_RAM.mem | grep -i "powershell.exe" | sort | uniq`
            This command searches for strings containing `powershell.exe`.  Keep in mind that simply finding the string "powershell.exe" doesn't guarantee that PowerShell was actually used; a more robust approach is to use Volatility's `cmdline` or `consoles` plugins.

        ![image](https://github.com/user-attachments/assets/7bc44feb-1904-461b-b162-679f0044ae24)

# Task 10: Identify and Investigate FTP Brute Force Attacks using Splunk

**Objective:** Use Splunk, a Security Information and Event Management (SIEM) platform, to analyze logs and identify potential FTP brute-force attacks. SIEM tools are essential for aggregating and analyzing logs from various sources to detect security incidents.

*   **Step 1: Splunk Installation**
    *   Successfully installed Splunk.  This is the prerequisite for using the platform.

    ![image](https://github.com/user-attachments/assets/33f6a42c-6d45-4319-b9d8-d5bbe018a427)

*   **Step 2: Log Inspection**
    *   Checked the logs within Splunk. This would typically involve importing logs from the relevant FTP server (or a file containing those logs) into Splunk. You'd then use Splunk's search language (SPL) to query the logs.  The specific SPL query used should be documented here.  It would likely look something like: `index=ftp_logs sourcetype=ftp | ...` (where `ftp_logs` is the index you create and `ftp` is a sourcetype you define).

    ![image](https://github.com/user-attachments/assets/df52e6c8-579f-452e-84cb-39441c840b58)

    * **Analysis (not pictured, but crucial):** To identify a brute-force attack, you would typically look for patterns like:
        *   A large number of failed login attempts from the same IP address within a short period.
        *   Attempts to log in with common usernames (e.g., "admin," "root," "test").
        *   Rapid-fire login attempts.
        *   You would use Splunk's SPL to create searches that identify these patterns.  For example:
           ```splunk
           index=ftp_logs sourcetype=ftp "Login failed"
           | stats count by src_ip
           | where count > 10  // Threshold for suspicious activity
           ```
           This search finds failed login events, counts the number of failures by source IP address, and then filters for IP addresses with more than 10 failed attempts (you'd adjust the threshold as needed).

# Task 11: Investigate Network Attacks using Kiwi Log Viewer

**Objective:** Use Kiwi Log Viewer, a log management tool, to analyze logs and identify a successful FTP login after a potential brute-force attack. This task complements Task 10 by using a different tool to examine the same (or similar) log data.

*   **Step 1: Log Analysis (Kiwi Log Viewer)**
    *   We examined the logs in Kiwi Log Viewer, focusing on FTP login events.

*   **Step 2: Identify Successful Login (Response Code 230)**
    *   We know that a successful FTP login typically results in a response code of 230 ("User logged in").  We searched for log entries containing this response code.  *Crucially*, in a real investigation, you would correlate this successful login with the *preceding* failed login attempts (from the brute-force attack) to confirm the attacker's success.  This often involves looking at timestamps and source IP addresses.

    ![image](https://github.com/user-attachments/assets/d3e10753-125d-4c38-b28a-739382c29dcf)

*   **Step 3: Identify Log ID**
    *   We identified log ID 8622 as corresponding to the successful login after the brute-force attack.  This ID can be used to refer to this specific event in reports or further analysis.

    ![image](https://github.com/user-attachments/assets/95dae9df-ca2a-4abb-ba7e-54868049090c)

# Thank
</details>
