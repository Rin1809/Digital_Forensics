# Digital_Forensics



# Task 1: Create a DD-format Image File

![image](https://github.com/user-attachments/assets/9ac2fee2-7629-457e-9d5f-1287ce2ff783)


*   Create a group for file creation, add the group to the file, assign permissions, and set access rights for the file and group.

![image](https://github.com/user-attachments/assets/f5dc2132-9029-4bf8-b62e-4319ee676c9f)


Samba Configuration


*   Create a user, set a Samba password for the newly created user, and add the user to the "nhomdieutra" (investigation) group.


![image](https://github.com/user-attachments/assets/40a3a8a3-ad95-4c89-8518-18d7507082f4)







*   Successfully mapped a network drive from the Kali Linux machine to the physical machine via Samba.











    *   However, the drive containing the documents is 500GB, so I'm redoing this with a virtual machine.














*   Successfully mapped to the virtual machine.


*   Drive E is here.  I will retrieve my data, where physical drive 0 is drive E.


*   Successfully collected a DD image file (.img) as shown below.


*   Checked the Kali Linux machine.

* Calculated the MD5 hash for the newly collected .img file.









Task 2: Convert the Image File from E01 to DD Format


*   Copied the file "Windows_001.E01" to the mapped drive on the Kali machine.


*   Converted the E01 file using `xmount` and mounted it in the same directory as the .E01 file.




Task 3: Mount the Image File on a Linux Workstation

*   Checked the files in `/mnt/dd`.



*   Used the following code snippet to calculate the MD5 hash of files in `/mnt/dd/images` and save the output to "yeucaubailab.txt".



*   Did the same for the "Songs" file.


*   Mounted the DD image file containing an Apple File System (APFS).

*   The path to calculate the MD5 hash of `.fseventsd` is…



*   Continued to use the above command to calculate hashes and save them to the text file.


*   Results








Task 4: Extract Hidden Content from the Hard Drive

*   `Phan_tich_Image.py` (Image_Analysis.py)











*   `phan_tich_image_pro.py` (Image_Analysis_Pro.py)




*   Browsed the home directory of user "roger" and then navigated to the "Downloads" directory.


*  `phan_tich_image_pro_max.py` (Image_Analysis_Pro_Max.py)

*   Added `host='0.0.0.0'` to allow access from other machines (the physical machine).















Task 5: Analyze the Windows Image File System

* View the partition table of `Windows_002.dd` using `mmls`.



* View the file system type and related operating system information using `fsstat`.















Other Entries:

*   **5: Root Directory:** The root directory of the file system, typically represented as "C:\" in Windows.  Contains entries for all files and directories at the top level of the volume.

*   **6: Volume Bitmap:** A special metadata file that tracks the allocation of clusters on the volume. Each bit in the bitmap corresponds to a cluster, with a value of 0 indicating a free cluster and 1 indicating an allocated cluster.

*   **9: $Secure:** A metadata file containing security information for files and directories on the volume. It defines access control lists (ACLs) to determine which users or groups have permission to access a specific file or directory.


*   **11: $Extend:** A special directory containing additional metadata files used to extend the functionality of the NTFS file system.  For example, it may contain information about disk quotas, system restore points, and other features.


Find the file or directory name in the corresponding inode.


Recover files from the image (.img) to the computer.






Task 6: Create and Analyze a File System Timeline using The Sleuth Kit (TSK)

Write temporal data to the file `ado.txt`.




Create the file `task4_timeline.txt` using `ado.txt` to view a timeline of activities performed on the suspect's machine from the Linux image.


Activity Analysis:

The timeline shows the initial creation of NTFS file system metadata ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend), followed by the creation of the `System Volume Information`, `Audio Files`, `images`, `Other Files`, `Outlook Files`, `Songs`, `text`, and `$RECYCLE.BIN` directories. The initial timestamps are all Thu Dec 19 2019 16:55:24, suggesting the file system may have been created or restored at that time.

Subsequent activities show access and modification of these directories at various times, such as accessing the `Outlook Files` directory at Thu Dec 19 2019 18:46:00.


Task 7: Analyze Common File Formats using a Hex Editor

Analyze "FileMau.docx" (SampleFile.docx)


Analyze "FileMau.gif" (SampleFile.gif)









Task 8: Collect Volatile Information from a Live Windows System






Four Tools in the PsTools Suite:











1.  **PsKill:** Terminates processes by name or process ID (PID).


    *   Example: Terminate a process named `SSH.exe` with PID 7388.
    *   Command:  `.\\pskill -t 7388`



2.  **PsList:** Provides detailed information about running processes on the system.

    *   Uses: Monitor system performance, identify resource-intensive processes, investigate suspicious activity.

    *   Command Example:  `.\\PsList -x`




3.  **PsLogList:** Views and manipulates event logs on Windows systems.


    *   Command Example:  `.\\PsLogList`

4.  **PsPing:** Similar to `ping` but with additional features and flexibility, especially the ability to test TCP connections.  It's useful for network connection testing and troubleshooting.




Task 9: Analyze a Windows RAM Image File

Understanding Handles, Memory Sections, Driver Modules, Device Tree, and Hooks in Redline:

1.  Driver Modules:

    *   The "Driver Modules" section in Redline displays a list of device drivers loaded into the system at the time Redline was run.
    *   Examining the "Driver Modules" section helps detect malicious or suspicious drivers. Malware often installs drivers to gain low-level control of the system. By checking the driver list, you can identify unwanted or unknown drivers.
    *   **Observation:**  A driver named `RamCaptureDriver64.SYS` was loaded into the system, which is quite unusual. The fact that a driver with a name suggesting RAM capture functionality is located in the `Downloads` directory of the `Administrator` account is a significant red flag.

        *   `\\??\\C:\\Users\\Administrator\\Downloads\\x64\\`: This is the path to the directory containing the driver.  The fact that the driver is in the `Downloads` directory of the `Administrator` account is suspicious. Drivers are usually installed in the `System32\\drivers` directory.












2.  Handles: 

Handles are pointers to system objects such as files, registry keys, processes, and threads. They are like references that allow programs to interact with these objects without needing to know their physical location in memory.

    *   **Application in Investigation:** Analyzing handles helps identify files opened by a specific process, registry keys being accessed, or active network connections. This information is useful for detecting suspicious behavior, such as a process trying to access a sensitive file or a network connection to a suspicious IP address.
    *   **Example:**
        *   **Registry Key Handles:**
            `HKEY_USERS\\...\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU`: Stores a list of programs that have been recently executed via the Run dialog.
            `HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`: Stores a list of programs that are automatically started when the user logs in, often exploited by malware.



















3.  Memory Sections:

    *   Based on the results of the "Hierarchical Processes" section, we see that the `spoolsv.exe` process (PID = 856) has been compromised, leading to the creation of child processes `rundll32.exe` and `cmd.exe`. The `notepad.exe` and `calc.exe` processes were then executed from `cmd.exe`. We can observe what they did through memory sections.

    *   It's normal for a print process like `spoolsv.exe` to access `locale.nls`, but since we know `spoolsv.exe` is compromised, we should also observe it.

    *   `user32.dll`, `kernel32.dll`, `ntdll.dll`: These are extremely important DLLs in Windows, providing basic functions for the user interface, system management, and low-level operations.  Almost every program uses them.








4.  Device Tree:

    *   The "Device Tree" section in Redline provides an overview of the system's device structure. It shows the devices connected to the system, as well as the relationships between them. Analyzing this section can help detect hidden or suspicious devices, which could be a sign of rootkits or other malware.
    *   As per section one, a sign of a drive inserted, and its child process name is RamCaptureDriver.

5.  **Hooks:**

    *   The "Hooks" section in Redline displays hooks installed in the system. A hook is a technique that allows a program to intercept and modify the behavior of other programs. While hooks can be used for legitimate purposes (such as debugging or monitoring), they are also often abused by malware to hide, steal information, or manipulate the system.

Other Volatility Plugins:

1.  **memdump:**

    *   Command Example:  `volatility_2.6_win64_standalone.exe -f "E:\\Dieu_tra_so\\Lab4-Resource\\Windows_RAM.mem" --profile=Win2008R2SP0x64 memdump -p 1896 -D "E:\\Dieu_tra_so\\Lab4-Resource\\task2"`
    *   This command dumps the entire process with PID 1896 to the destination directory.

2.  **cmdline:**

    *   Displays the command line used to start each process.

3.  **filescan:**

    *   Scans memory to find files, including deleted files that still have data in memory.

4. **driverscan**
    * Scans memory to look for loaded drivers, including hidden or rootkit-concealed drivers.

Using the `strings` Command to Further Analyze `Windows_RAM.mem` :

1.  **Extract Domain Names (.com, .net, .org):**

    *   To extract domain names with `.com`, `.net`, and `.org` extensions, use this command:
        `strings Windows_RAM.mem | grep -E '\\.(com|net|org)' | sort | uniq`
    *   The result of this command is a list of domain names found in memory, including both valid and invalid domain names.

2.  **Extract Email Addresses:**

    *   To extract email addresses, use this command:
        `strings Windows_RAM.mem | grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' | sort | uniq`

3.  **List Commands Likely Run on the System via cmd and PowerShell:**

    *   **For `cmd`:**
        `strings Windows_RAM.mem | grep -i "cmd.exe " | sort | uniq`
        This command searches for strings containing `cmd.exe`.
    * Using volatility to check the command line of cmd.

    *   **For PowerShell:**
        `strings Windows_RAM.mem | grep -i "powershell.exe" | sort | uniq`
        This command searches for strings containing `powershell.exe`.

Task 10: Open the SAM, SECURITY, and SYSTEM Files in Hex Workshop to View Their Contents.  Report on Information Deemed Useful.

1.  **SAM File**

2.  **SECURITY File**

3.  **SYSTEM File**


