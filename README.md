<details>
   
<summary><h1>This repository, i just want to show what Digital Forensics work (doing realistic simulation lab ). If care about it so span it down ᓚᘏᗢ </h1></summary>
   
# Digital_Forensics

![image](https://github.com/user-attachments/assets/da81535d-c9e2-4d72-a2eb-6c07bf2e6f52)


# Task 1: Create a DD-format Image File

![image](https://github.com/user-attachments/assets/9ac2fee2-7629-457e-9d5f-1287ce2ff783)


*   Create a group for file creation, add the group to the file, assign permissions, and set access rights for the file and group.

![image](https://github.com/user-attachments/assets/f5dc2132-9029-4bf8-b62e-4319ee676c9f)


Samba Configuration


*   Create a user, set a Samba password for the newly created user, and add the user to the "nhomdieutra" (investigation) group.


![image](https://github.com/user-attachments/assets/40a3a8a3-ad95-4c89-8518-18d7507082f4)







*   Successfully mapped a network drive from the Kali Linux machine to the physical machine via Samba.


![image](https://github.com/user-attachments/assets/f14ae1e3-56f4-4311-af25-b37ef9986e15)









*   However, the drive containing the documents is 500GB, so I'm redoing this with a virtual machine.

![image](https://github.com/user-attachments/assets/fb2add65-4fda-4c7e-97d5-ba04d6300053)













*   Successfully mapped to the virtual machine.

![image](https://github.com/user-attachments/assets/9e370bd2-53ef-4cfe-87b5-a71f06c290e8)


*   Drive E is here.  I will retrieve my data, where physical drive 0 is drive E.

![image](https://github.com/user-attachments/assets/b9e04084-3d47-46d9-97f8-f0004c72928d)

*   Successfully collected a DD image file (.img) as shown below.
![image](https://github.com/user-attachments/assets/d656eba5-dbd2-4d8b-80e2-ece70e4931df)


*   Checked the Kali Linux machine.

![image](https://github.com/user-attachments/assets/e2dc0d45-1e38-4fb8-b925-f24515a7ea3c)


* Calculated the MD5 hash for the newly collected .img file.


![image](https://github.com/user-attachments/assets/3102fae5-3190-4470-8d7e-30a8733edc74)







# Task 2: Convert the Image File from E01 to DD Format


*   Copied the file "Windows_001.E01" to the mapped drive on the Kali machine.

![image](https://github.com/user-attachments/assets/d7115474-e47a-4cb7-a6df-e4c8994cd6c2)

*   Converted the E01 file using `xmount` and mounted it in the same directory as the .E01 file.


![image](https://github.com/user-attachments/assets/f37c4d3b-473a-4f40-9931-94563d54f090)



# Task 3: Mount the Image File on a Linux Workstation

*   Checked the files in `/mnt/dd`.


![image](https://github.com/user-attachments/assets/8cbf9276-9bd9-4589-bec8-6ef808223639)
![image](https://github.com/user-attachments/assets/53ef2679-1f02-4fb9-b557-b54df49a78cf)
![image](https://github.com/user-attachments/assets/603529df-5f00-4e48-8ed3-b607175e183a)


*   Used the following code snippet to calculate the MD5 hash of files in `/mnt/dd/images` and save the output to "yeucaubailab.txt".

![image](https://github.com/user-attachments/assets/a88ecb29-90af-4da0-9d86-91fc4a3e2eb7)

![image](https://github.com/user-attachments/assets/ecbe52ef-9a93-4d37-b2e0-5e0acf40fc58)

*   Did the same for the "Songs" file.

![image](https://github.com/user-attachments/assets/656a2f4d-c805-4a15-a4b0-fe1e144e4be9)

*   Mounted the DD image file containing an Apple File System (APFS).

![image](https://github.com/user-attachments/assets/4e46772b-c242-424f-8853-73d9af7e9948)

*   The path to calculate the MD5 hash of `.fseventsd` is…

![image](https://github.com/user-attachments/assets/34056b0c-840f-443b-90ad-b622278c7ed0)

![image](https://github.com/user-attachments/assets/97d5345e-a02a-4545-8499-223868d0a24f)


*   Continued to use the above command to calculate hashes and save them to the text file.

![image](https://github.com/user-attachments/assets/0d503e45-7bfe-4698-b432-7adaf70c0a19)


*   Results



![image](https://github.com/user-attachments/assets/2083c720-35a9-4159-b162-4996486d0f99)





# Task 4: Extract Hidden Content from the Hard Drive

*   `Phan_tich_Image.py` (Image_Analysis.py)



![image](https://github.com/user-attachments/assets/059545f4-ead6-4089-90ef-7c5405166da6)








*   `phan_tich_image_pro.py` (Image_Analysis_Pro.py)

![image](https://github.com/user-attachments/assets/106c14e8-a4a7-4f37-9601-e00a7e5a5a6c)
![image](https://github.com/user-attachments/assets/63d7b60c-28cc-4333-b029-fcd292809a50)


*   Browsed the home directory of user "roger" and then navigated to the "Downloads" directory.

![image](https://github.com/user-attachments/assets/6635d2c1-7026-4636-864b-2a423f3e0664)



*  `phan_tich_image_pro_max.py` (Image_Analysis_Pro_Max.py)

![image](https://github.com/user-attachments/assets/5eb9c477-a010-4fdc-a3e7-28a8164d465f)

*   Added `host='0.0.0.0'` to allow access from other machines (the physical machine).


![image](https://github.com/user-attachments/assets/7fadfc17-8f71-4031-a182-12a313c9644f)
![image](https://github.com/user-attachments/assets/6e114bb2-fe2f-4a6e-ac6a-c4a2dd0eb345)













# Task 5: Analyze the Windows Image File System

* View the partition table of `Windows_002.dd` using `mmls`.

![image](https://github.com/user-attachments/assets/1684fac8-6405-4523-8b06-6bea83689b9f)


* View the file system type and related operating system information using `fsstat`.


![image](https://github.com/user-attachments/assets/c9a15a7b-3710-433a-86fb-11bd4bae75bd)













Other Entries:

*   **5: Root Directory:** The root directory of the file system, typically represented as "C:\" in Windows.  Contains entries for all files and directories at the top level of the volume.


![image](https://github.com/user-attachments/assets/7fd3144f-78cc-4713-92e6-ab5c8f9d0aed)

*   **6: Volume Bitmap:** A special metadata file that tracks the allocation of clusters on the volume. Each bit in the bitmap corresponds to a cluster, with a value of 0 indicating a free cluster and 1 indicating an allocated cluster.


![image](https://github.com/user-attachments/assets/ef402b42-d095-4b97-a1e2-85c3c97fa6ed)

*   **9: $Secure:** A metadata file containing security information for files and directories on the volume. It defines access control lists (ACLs) to determine which users or groups have permission to access a specific file or directory.

![image](https://github.com/user-attachments/assets/2f72d569-cfde-4e52-9c21-e36f59b4766e)

*   **11: $Extend:** A special directory containing additional metadata files used to extend the functionality of the NTFS file system.  For example, it may contain information about disk quotas, system restore points, and other features.

![image](https://github.com/user-attachments/assets/646ea15d-fb57-43ac-8439-cc38d315a814)

Find the file or directory name in the corresponding inode.

![image](https://github.com/user-attachments/assets/8015aa79-57a9-4543-bc30-861205008ea2)

Recover files from the image (.img) to the computer.

![image](https://github.com/user-attachments/assets/984c2c15-37f9-47d5-9e5c-5a40aeae5889)





# Task 6: Create and Analyze a File System Timeline using The Sleuth Kit (TSK)

Write temporal data to the file `ado.txt`.

![image](https://github.com/user-attachments/assets/1437e3db-5915-4b45-a71b-932cb12b065c)
![image](https://github.com/user-attachments/assets/a8344012-f94b-40eb-a6fb-c490f165ca10)

![image](https://github.com/user-attachments/assets/c70ec20c-4f15-4e9c-b090-22b1fcb86f26)


Create the file `task4_timeline.txt` using `ado.txt` to view a timeline of activities performed on the suspect's machine from the Linux image.


![image](https://github.com/user-attachments/assets/83587142-b8d2-4937-9243-d461d52cccb6)


Activity Analysis:

The timeline shows the initial creation of NTFS file system metadata ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend), followed by the creation of the `System Volume Information`, `Audio Files`, `images`, `Other Files`, `Outlook Files`, `Songs`, `text`, and `$RECYCLE.BIN` directories. The initial timestamps are all Thu Dec 19 2019 16:55:24, suggesting the file system may have been created or restored at that time.


Subsequent activities show access and modification of these directories at various times, such as accessing the `Outlook Files` directory at Thu Dec 19 2019 18:46:00.


![image](https://github.com/user-attachments/assets/2cf933d3-7885-46f3-91f5-27ba3984a42c)


# Task 7: Analyze Common File Formats using a Hex Editor

Analyze "FileMau.docx" (SampleFile.docx)
![image](https://github.com/user-attachments/assets/1c14c739-3336-4201-8642-1c1fae2126f9)


Analyze "FileMau.gif" (SampleFile.gif)

![image](https://github.com/user-attachments/assets/01f5f036-697a-44f0-8b05-8543d825b0a8)








# Task 8: Collect Volatile Information from a Live Windows System






Four Tools in the PsTools Suite:


![image](https://github.com/user-attachments/assets/c77ae841-b488-4c30-a378-23a1e2976cab)









1.  **PsKill:** Terminates processes by name or process ID (PID).

![image](https://github.com/user-attachments/assets/f18dbc40-d2f4-4aa9-a4d7-eaab00e738d8)

 *   Example: Terminate a process named `SSH.exe` with PID 7388.
 *   Command:  `.\\pskill -t 7388`



2.  **PsList:** Provides detailed information about running processes on the system.
![image](https://github.com/user-attachments/assets/d5657972-0698-4d95-b61c-3f4a83a92d49)

    *   Uses: Monitor system performance, identify resource-intensive processes, investigate suspicious activity.

    *   Command Example:  `.\\PsList -x`




3.  **PsLogList:** Views and manipulates event logs on Windows systems.
![image](https://github.com/user-attachments/assets/8e1e539a-d425-4623-add6-aa224baf9aef)


    *   Command Example:  `.\\PsLogList`

4.  **PsPing:** Similar to `ping` but with additional features and flexibility, especially the ability to test TCP connections.  It's useful for network connection testing and troubleshooting.
![image](https://github.com/user-attachments/assets/01e6420f-4b6d-4e5e-ace2-a7b573c776f3)




# Task 9: Analyze a Windows RAM Image File

Understanding Handles, Memory Sections, Driver Modules, Device Tree, and Hooks in Redline:

1.  Driver Modules:

    *   The "Driver Modules" section in Redline displays a list of device drivers loaded into the system at the time Redline was run.
    *   Examining the "Driver Modules" section helps detect malicious or suspicious drivers. Malware often installs drivers to gain low-level control of the system. By checking the driver list, you can identify unwanted or unknown drivers.
    *   **Observation:**  A driver named `RamCaptureDriver64.SYS` was loaded into the system, which is quite unusual. The fact that a driver with a name suggesting RAM capture functionality is located in the `Downloads` directory of the `Administrator` account is a significant red flag.
![image](https://github.com/user-attachments/assets/b95d613e-844d-47e1-a750-4da7c6533d7d)

        *   `\\??\\C:\\Users\\Administrator\\Downloads\\x64\\`: This is the path to the directory containing the driver.  The fact that the driver is in the `Downloads` directory of the `Administrator` account is suspicious. Drivers are usually installed in the `System32\\drivers` directory.












2.  Handles: 

Handles are pointers to system objects such as files, registry keys, processes, and threads. They are like references that allow programs to interact with these objects without needing to know their physical location in memory.

   *   **Application in Investigation:** Analyzing handles helps identify files opened by a specific process, registry keys being accessed, or active network connections. This information is useful for detecting suspicious behavior, such as a process trying to access a sensitive file or a network connection to a suspicious IP address.
    *   **Example:**
        *   **Registry Key Handles:**
            `HKEY_USERS\\...\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU`: Stores a list of programs that have been recently executed via the Run dialog.
            `HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`: Stores a list of programs that are automatically started when the user logs in, often exploited by malware.



![image](https://github.com/user-attachments/assets/2a293d7f-23a9-41ce-a6c7-e75f40d8c2eb)

![image](https://github.com/user-attachments/assets/cd8ae2a0-e86d-4484-8a2c-0eae495ec03d)
![image](https://github.com/user-attachments/assets/c0a69fdc-7a3b-484f-8f91-b864ebef8aee)















3.  Memory Sections:

   *   Based on the results of the "Hierarchical Processes" section, we see that the `spoolsv.exe` process (PID = 856) has been compromised, leading to the creation of child processes `rundll32.exe` and `cmd.exe`. The `notepad.exe` and `calc.exe` processes were then executed from `cmd.exe`. We can observe what they did through memory sections.
  

![image](https://github.com/user-attachments/assets/949ad7d1-85b2-4e1d-9ddc-1d8db41c0077)

    
   *   It's normal for a print process like `spoolsv.exe` to access `locale.nls`, but since we know `spoolsv.exe` is compromised, we should also observe it.


![image](https://github.com/user-attachments/assets/dc9ad625-4155-4548-88d3-0a934a212b28)

   *   `user32.dll`, `kernel32.dll`, `ntdll.dll`: These are extremely important DLLs in Windows, providing basic functions for the user interface, system management, and low-level operations.  Almost every program uses them.








4.  Device Tree:

    *   The "Device Tree" section in Redline provides an overview of the system's device structure. It shows the devices connected to the system, as well as the relationships between them. Analyzing this section can help detect hidden or suspicious devices, which could be a sign of rootkits or other malware.
    *   As per section one, a sign of a drive inserted, and its child process name is RamCaptureDriver.
![image](https://github.com/user-attachments/assets/ac4c4741-7ad7-428a-b02e-2c3d5fb02691)

5.  **Hooks:**

    *   The "Hooks" section in Redline displays hooks installed in the system. A hook is a technique that allows a program to intercept and modify the behavior of other programs. While hooks can be used for legitimate purposes (such as debugging or monitoring), they are also often abused by malware to hide, steal information, or manipulate the system.
![image](https://github.com/user-attachments/assets/d909c35c-77f4-461b-be90-612b5e1d75b4)

# Other Volatility Plugins:

1.  **memdump:**

    *   Command Example:  `volatility_2.6_win64_standalone.exe -f "E:\\Dieu_tra_so\\Lab4-Resource\\Windows_RAM.mem" --profile=Win2008R2SP0x64 memdump -p 1896 -D "E:\\Dieu_tra_so\\Lab4-Resource\\task2"`
    *   This command dumps the entire process with PID 1896 to the destination directory.
  
   

![image](https://github.com/user-attachments/assets/2889a1a2-a34c-4cb9-86cb-f45fbf4813b9)

![image](https://github.com/user-attachments/assets/bef104e5-074c-4e5e-adee-2c5bd41e1a31)

2.  **cmdline:**

    *   Displays the command line used to start each process.
  


![image](https://github.com/user-attachments/assets/e83df515-8c82-4358-a3e7-7005c6f2b656)

3.  **filescan:**

    *   Scans memory to find files, including deleted files that still have data in memory.
  

![image](https://github.com/user-attachments/assets/eb91fb12-f72d-4010-8025-dae7ba79d94f)

4. **driverscan**
    * Scans memory to look for loaded drivers, including hidden or rootkit-concealed drivers.

  

![image](https://github.com/user-attachments/assets/9b1a0cc2-f239-4ac0-b17a-69c337adb4b8)

# Using the `strings` Command to Further Analyze `Windows_RAM.mem` :

1.  **Extract Domain Names (.com, .net, .org):**

    *   To extract domain names with `.com`, `.net`, and `.org` extensions, use this command:
        `strings Windows_RAM.mem | grep -E '\\.(com|net|org)' | sort | uniq`
    *   The result of this command is a list of domain names found in memory, including both valid and invalid domain names.
  

![image](https://github.com/user-attachments/assets/4ddf48d8-64ac-4d38-953d-b91bebee70c6)


![image](https://github.com/user-attachments/assets/a9dfc65c-5d92-44b5-8c34-989afe0dce51)

![image](https://github.com/user-attachments/assets/92648d62-df08-4edc-9090-55eca2ad1391)

3.  **Extract Email Addresses:**

    *   To extract email addresses, use this command:
        `strings Windows_RAM.mem | grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' | sort | uniq`
![image](https://github.com/user-attachments/assets/a1cbd257-11b1-448f-a20f-c08194585ebd)

4.  **List Commands Likely Run on the System via cmd and PowerShell:**

    *   **For `cmd`:**
        `strings Windows_RAM.mem | grep -i "cmd.exe " | sort | uniq`
        This command searches for strings containing `cmd.exe`.
    * Using volatility to check the command line of cmd.

  
  
![image](https://github.com/user-attachments/assets/c83c7856-e34e-4d4d-9927-271cb340c635)

   *   **For PowerShell:**
        `strings Windows_RAM.mem | grep -i "powershell.exe" | sort | uniq`
        This command searches for strings containing `powershell.exe`.


![image](https://github.com/user-attachments/assets/7bc44feb-1904-461b-b162-679f0044ae24)


# Task 10: Identify and Investigate FTP Brute Force Attacks using Splunk

*   Successfully installed Splunk.

![image](https://github.com/user-attachments/assets/33f6a42c-6d45-4319-b9d8-d5bbe018a427)


*   Checked the logs.

![image](https://github.com/user-attachments/assets/df52e6c8-579f-452e-84cb-39441c840b58)


# Task 11: Investigate Network Attacks using Kiwi Log Viewer

*   The log IDs show that the attacker successfully logged in.
*   Since we know a successful login has a response code of 230 (User logged in - Response: 230), we will search for that.
*   We will search for responses with code 230.

![image](https://github.com/user-attachments/assets/d3e10753-125d-4c38-b28a-739382c29dcf)


*   Result: The log ID for the successful brute-force is 8622.


![image](https://github.com/user-attachments/assets/95dae9df-ca2a-4abb-ba7e-54868049090c)



# Thank 

</details>
