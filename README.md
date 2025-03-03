<details>

<summary><h1>This repository, no coding. As a student learning about cyber security, i just want to show what i did and how digital forensics work (doing realistic simulation lab ). If care about it so expan it down ᓚᘏᗢ </h1></summary>

# Digital_Forensics

![image](https://github.com/user-attachments/assets/da81535d-c9e2-4d72-a2eb-6c07bf2e6f52)

This repository documents a series of digital forensics exercises performed in a simulated lab environment.  Each task demonstrates a key aspect of a digital forensics investigation, from image acquisition to memory analysis.  The goal is to provide a practical, hands-on understanding of the tools and techniques used in real-world digital forensics investigations.

# Task 0: Initial File Analysis and Question Answering 

**Objective:** This task serves as an introductory exercise to familiarize you with basic digital forensics techniques. You will be analyzing a provided file, likely containing encoded or hidden information related to a simulated investigation. The goal is to decode this information, answer specific questions based on the extracted data, and understand how seemingly simple tasks can reveal crucial clues in a digital forensics scenario.  This task emphasizes the importance of observation, decoding, and targeted analysis.

![image](https://github.com/user-attachments/assets/5fa1670e-5425-420a-b8da-8f55f65804cb)

Opening the initial file reveals a section of data recorded in hexadecimal format. **Why is data sometimes in hex?** Hexadecimal (base-16) is a common way to represent binary data in a human-readable format. Computers work with binary (0s and 1s), but hex is more compact and easier for humans to read and write than long strings of binary digits.  In forensics, hex representation is often used for:

*   **Examining raw data:** Viewing the exact bytes of a file or disk image.
*   **Identifying file signatures:**  Recognizing file types by their header bytes (often viewed in hex).
*   **Analyzing network packets:**  Looking at the byte-level structure of network communication.
*   **Debugging and reverse engineering:**  Understanding the low-level workings of software.

**Step 1: Decoding Hexadecimal Data to ASCII**

To understand the hex data, we need to convert it to a more readable format, typically ASCII text. ASCII (American Standard Code for Information Interchange) is a character encoding standard that represents text in computers.

**How to Convert Hex to ASCII:**

*   **Online Hex to ASCII Converters:** Numerous online tools are available (just search for "hex to ascii converter"). You can copy and paste the hex data into these tools to get the ASCII output.
*   **Command-line Tools (Linux/macOS):**  You can use tools like `xxd -r -p` or `echo "hex_data" | xxd -r -p | strings` in a terminal.
*   **Hex Editors:**  Hex editors often have built-in functionality to interpret hex data as ASCII or other character encodings.

After converting the hex format, the data can be decoded into ASCII for reading. This reveals human-readable text, which is much easier to analyze.

![image](https://github.com/user-attachments/assets/8c8f64f9-cc5e-4256-82ec-51012e891b51)

Now we can proceed to answer the specific questions based on this decoded ASCII text.

*   **Question 1:** What is the website of the chat software that Nhung used?

     ![image](https://github.com/user-attachments/assets/a11d8035-010c-4b69-836b-ad79d44ffc9e)

    *   **Step:** Examine the decoded ASCII text. Look for patterns that resemble website addresses (e.g., starting with "www." or containing ".com", ".co", etc.). In the decoded text, you can clearly see "Website chat cua Nhung la: www.e-chat.co".
    *   **Answer:** `www.e-chat.co`
    *   **Why is this question relevant?**  Identifying the chat software used can be important for several reasons:
        *   **Context:** It provides context about Nhung's online activities and communication methods.
        *   **Further Investigation:** Knowing the chat software might lead to further investigation of chat logs, account information, or vulnerabilities associated with that specific platform.
        *   **Link Analysis:**  It could be a starting point for link analysis if the chat software is known to be used for illicit activities.

*   **Question 2:** The location where Nhung hid the USB drive, answer in Vietnamese without accents as in the investigation result:

*   ![image](https://github.com/user-attachments/assets/8e7548ef-c3ec-4426-8d23-0ad2ff520f19)

    *   **Step:**  Continue examining the decoded ASCII text. Look for phrases that indicate a location or hiding place.  The text reads: "Noi Nhung giau USB la: chau cay".
    *   **Answer:** `chau cay` (chậu cây - flower pot)
    *   **Why is this question relevant?**  Knowing the hiding location of physical evidence (like a USB drive) is crucial for:
        *   **Physical Evidence Recovery:**  Directly leading investigators to the location where the USB drive might be physically hidden.
        *   **Corroboration:**  Confirming details from other sources (e.g., witness statements) with physical evidence.
        *   **Understanding Intent:** The hiding place itself might provide clues about the person's intent to conceal information.

*   **Question 3:** What method did the attacker use to exploit the system? We can see continuous and unusual failed login attempts by examining the `auth.log` file, starting from April. We can also check for unusual failed logins --> Burt-Force

  ![image](https://github.com/user-attachments/assets/9b227fe3-e5d0-47a6-ba85-216a2f8b1d7a)
  ![image](https://github.com/user-attachments/assets/c8aebcf7-a761-4bfe-b2a9-7b0a84a3609f)
    *   **Step:** The question itself provides the answer by referencing "continuous and unusual failed login attempts" and "Burt-Force".  "Burt-Force" is likely a typo and meant to be "Brute-Force".  Brute-force attacks are characterized by numerous attempts to guess passwords or usernames.  The images show log entries from `auth.log` which is a common log file on Linux systems that records authentication attempts.  The repeated "Failed password for invalid user" entries strongly suggest a brute-force attack.
    *   **Answer:** `Brute-Force`
    *   **Why is this question relevant?**  Identifying the attack method is fundamental in incident response and forensics:
        *   **Understanding Attack Vectors:** Knowing the method helps understand how the attacker gained (or attempted to gain) access.
        *   **Assessing Damage:**  The type of attack can indicate the potential scope of compromise. A brute-force attack, if successful, can lead to unauthorized access and further malicious activities.
        *   **Remediation:** Knowing the attack method is essential for implementing appropriate security measures to prevent future attacks of the same type (e.g., strengthening passwords, implementing account lockout policies, using multi-factor authentication).

*   **Question 4:** How many IPs performed the attack? How many of them successfully attacked?

    Based on classifying these IP addresses, they appear to be targets of brute force, based on the high number of login attempts associated with them (limited to the April attack period).

    *(The list of IPs and attempt counts is provided in the original document - no image is needed here)*

    *   **Step 1: Count the Number of Attacking IPs:**  Count the number of unique IP addresses listed in the provided data that are associated with failed login attempts.  The list provides 24 unique IP addresses.
    *   **Step 2: Identify IPs with Successful Logins:** Examine the subsequent data that shows IPs with "successful logins (Accept)". Identify the IPs from the brute-force list that also appear in the successful login list. In this case, 6 IPs are listed with successful logins.
    *   **Answer (Number of Attacking IPs):** `24`
    *   **Answer (Number of IPs with Successful Attacks):** `6`
    *   **Why is this question relevant?**  Identifying attacking IPs and successful IPs helps to:
        *   **Scope of Attack:**  Understand the scale of the brute-force attempt and how many entry points might have been compromised.
        *   **Attribution (Initial Clues):** IP addresses can provide initial clues for tracing back the attacker or the origin of the attack, although IP addresses can be spoofed or originate from compromised systems.
        *   **Blocking and Mitigation:**  IP addresses of attackers can be used to block further malicious activity (e.g., using firewalls or intrusion prevention systems).
        *   **Prioritization:**  IPs with successful logins are of higher priority for further investigation as they represent actual compromises.

    ![image](https://github.com/user-attachments/assets/d7554195-57f0-414f-bbe9-ed8e5fe6a360)


    Based on this, we can also see which IPs successfully logged in. If we compare with the IPs that had failed attempts above, we get:

    *(The list of IPs with successful logins is provided in the original document - no image is needed here)*

    *   --> Depending on how many attempts are considered brute force, we can infer that there were 24 attacking IPs and 6 IPs with successful attacks.

*   **Question 5:** Which users were newly created during the attack process?
*   ![image](https://github.com/user-attachments/assets/6c84b070-126f-490e-9f91-0fbd144269f5)

    *   **Step:** Examine the provided image which likely shows log entries related to user creation (`useradd` command is visible).  Identify usernames that were created around the time of the brute-force attack (as indicated in the question). The text identifies `packet`, `wind3str0y`, `fido`, `dhg` as users created during the attack, and differentiates them from `user1`, `user2`, `user4` which seem to be pre-existing legitimate users.
    *   **Answer:** `packet`, `wind3str0y`, `fido`, `dhg`
    *   **Why is this question relevant?**  Identifying newly created users during an attack timeframe is a strong indicator of malicious activity:
        *   **Backdoors and Persistence:** Attackers often create new user accounts to establish backdoors for persistent access to the compromised system.
        *   **Privilege Escalation:**  New accounts could be created for privilege escalation attempts or to perform actions under a different user context.
        *   **Account Compromise Confirmation:**  User creation often follows a successful brute-force attack, indicating that the attacker gained initial access and then proceeded to further compromise the system.

*   **Question 6:** What system scanning tool did the attacker install on this Linux Server?

      ![image](https://github.com/user-attachments/assets/c22e76ce-fdaa-4110-a6fd-1e617e524296)

    *   **Step:** Examine the `term.log` image (likely representing terminal or command history logs). Look for commands related to software installation or system utilities. The image clearly shows the command `apt-get install nmap`. `apt-get` is a package manager on Debian-based Linux systems, and `nmap` is a well-known network scanning tool.
    *   **Answer:** `Nmap`
    *   **Why is this question relevant?**  Identifying installed tools, especially security or network scanning tools, can reveal the attacker's post-exploitation activities:
        *   **Reconnaissance:**  `Nmap` is used for network reconnaissance - scanning for open ports and services on the target system or network. This could indicate the attacker was mapping the network to find further targets or vulnerabilities.
        *   **Lateral Movement:**  Scanning tools can be used to identify other vulnerable systems on the internal network for lateral movement (spreading the compromise).
        *   **Information Gathering:**  Attackers use scanning to gather information about the target system's configuration and security posture.

*   **Question 7:** The attacker used the social network Twitter to send images from the compromised computer. Identify the account and password that the attacker used to log in to Twitter.

*   ![image](https://github.com/user-attachments/assets/64ae2c74-a2bf-4b4c-b540-9a1c78f90155)


    In file number 3, there is a capture with the host `twitter.com`. When opened, we can see its Authorization hash, in base64 format.  When decoded:

    ![image](https://github.com/user-attachments/assets/8ba08790-3edf-4089-afd5-80ed9fe0e2a4)
    ![image](https://github.com/user-attachments/assets/17779deb-8a9f-4dcd-b96f-d1a1b26071c7)

    *   **Step 1: Identify Relevant File:** The question states "file number 3" and mentions "twitter.com". This suggests examining a network capture file (like a `.pcap` or similar) and looking for traffic related to Twitter. The image shows a Wireshark capture ("file number 3") with "twitter.com" as the host.
    *   **Step 2: Examine Authorization Header:** The text mentions "Authorization hash, in base64 format". In HTTP requests, authorization information is often passed in the "Authorization" header.  The image shows an "Authorization" header in the HTTP request to `twitter.com`.
    *   **Step 3: Decode Base64:**  The Authorization value is in Base64 encoding. Base64 is a common encoding scheme to represent binary data as ASCII text.  You can use online Base64 decoders or command-line tools like `base64 -d` (Linux/macOS) or PowerShell's `[System.Convert]::FromBase64String()` to decode the hash.  The images show the Base64 encoded hash and the decoded output, revealing "userforlab:passforlab".
    *   **Answer (Account):** `userforlab`
    *   **Answer (Password):** `passforlab`
    *   **Why is this question relevant?**  Identifying compromised social media accounts used by attackers is important for:
        *   **Data Exfiltration:**  Social media can be used as a channel for exfiltrating stolen data from a compromised system.
        *   **Command and Control (C2):** In some cases, attackers might use social media for covert command and control communication with malware.
        *   **Attribution and Tracking:** Social media accounts can provide further clues for tracing the attacker's identity or activities.
        *   **Account Remediation:**  Compromised accounts need to be secured (passwords changed, accounts potentially suspended) to prevent further misuse.

*   **Question 8:** The attacker connected to the internal network and stole the FTP account of a user in the company. Find the attacker's IP address.

    After using Wireshark:

      ![image](https://github.com/user-attachments/assets/0498cfd5-f6dd-46e1-bb8b-86ca881a0be9)

    *   **Step:** The question mentions "Wireshark" and "FTP account".  This indicates analyzing a network capture (likely a `.pcap` file) using Wireshark to examine FTP traffic. The image shows a Wireshark capture filtered for FTP protocol.  The text points to the source IP address of the FTP requests ("USER, PASS, SYST, PORT, LIST, RETR, QUIT") as `192.168.0.117`.
    *   **Answer:** `192.168.0.117`
    *   **Why is this question relevant?**  Identifying the attacker's IP address within the internal network is crucial for:
        *   **Internal Network Mapping:**  Understanding the attacker's location and movement within the internal network.
        *   **Identifying Compromised Internal Systems:**  The attacker's IP address might be associated with a compromised internal system that was used as a staging point for further attacks.
        *   **Network Segmentation and Security:**  This information can inform network segmentation strategies and security controls to limit lateral movement and contain future breaches.

*   **Question 9:** What are the stolen FTP account and password?


    After using Wireshark:

    ![image](https://github.com/user-attachments/assets/49253270-a360-473b-a8f2-d66b1d394b5f)

    *   **Step:** Continue analyzing the Wireshark FTP capture. Look for FTP commands that transmit credentials, specifically `USER` and `PASS` commands. FTP, in its basic form, transmits usernames and passwords in plain text. Wireshark can capture and display these commands. The image highlights the `USER ketoan` and `PASS ispace` commands in the Wireshark capture.
    *   **Answer (Account):** `ketoan`
    *   **Answer (Password):** `ispace`
    *   **Why is this question relevant?**  Identifying stolen credentials (like FTP accounts) is critical because:
        *   **Unauthorized Access:** Stolen FTP credentials can be used to gain unauthorized access to sensitive file servers and data.
        *   **Data Breach:**  Compromised FTP accounts are often used to steal data from the FTP server or upload malware.
        *   **Account Remediation:**  Stolen accounts need to have their passwords reset immediately and potentially be locked down to prevent further misuse.
        *   **Security Policy Review:**  The fact that FTP credentials were stolen in plain text highlights a security vulnerability (using unencrypted FTP) that needs to be addressed.

*   **Question 10:** Find the file that was leaked when the attacker exploited FTP and determine the MD5 hash of that file.

*   ![image](https://github.com/user-attachments/assets/9966e278-20e5-49b9-88ea-9137a1ee62d5)


    Proceed to export a target file from Wireshark.

    Using the `Get-FileHash` command on PowerShell, we can calculate the MD5 hash of the newly exported file, which is "file-mat.docx".
    ![image](https://github.com/user-attachments/assets/949bd198-481e-4a66-b4c1-243ed343abb5)

    *   **Step 1: Identify Data Transfer in Wireshark:** Examine the Wireshark FTP capture for commands that indicate data transfer, such as `RETR` (retrieve file). The image shows a `RETR file-mat.docx` command. This indicates the attacker downloaded the file "file-mat.docx" via FTP.
    *   **Step 2: Export the File from Wireshark:** Wireshark allows you to export objects or files that are transmitted within network streams.  In Wireshark, you would typically right-click on the relevant FTP packet (e.g., a packet related to the `RETR` command or data transfer) and use "Follow TCP Stream" or "Export Objects" to save the file "file-mat.docx" from the captured network traffic.
    *   **Step 3: Calculate MD5 Hash:** Once you have exported the "file-mat.docx" file, calculate its MD5 hash. The example uses PowerShell's `Get-FileHash` command: `Get-FileHash -Algorithm MD5 -Path "file-mat.docx"`.  You can use other tools like `md5sum` (Linux/macOS) or online MD5 hash calculators. *The MD5 hash value itself should be recorded here in a real investigation.*
    *   **Answer (File Name):** `file-mat.docx`
    *   **Answer (MD5 Hash):** *(The MD5 hash value of "file-mat.docx" would be inserted here after calculation)*
    *   **Why is this question relevant?**  Identifying the leaked file and its hash is crucial for:
        *   **Data Breach Confirmation:**  Confirming what specific data was stolen by the attacker.
        *   **Data Sensitivity Assessment:**  Determining the sensitivity and value of the leaked file (e.g., is it confidential business data, personal information, etc.).
        *   **Impact Assessment:**  Evaluating the potential impact of the data breach on the organization or individuals.
        *   **Data Integrity Verification:**  The MD5 hash of the leaked file can be compared to the original file (if available) to verify if the file was modified during or after the exfiltration.

*   **Question 11:** Ann's computer with IP address (192.168.1.158) sent a message over the wireless network to a strange computer that just connected to the network. Analyze the `pcap1.pcap` file to determine the account name that Ann used to log into the messaging system.
![image](https://github.com/user-attachments/assets/7d2897a9-831f-4111-b9a7-c6257074bc03)

    *   **Step:** Analyze the `pcap1.pcap` file (presumably another Wireshark capture) focusing on traffic from Ann's computer (IP `192.168.1.158`) to a "strange computer" that recently connected to the network. The question mentions "messaging system". Examine network protocols and traffic patterns that might be related to messaging or chat applications. The image seems to show traffic related to some sort of messaging protocol.  The text points to "account name that Ann used to log into the messaging system" and provides the answer "user1".  *More detail is needed on how "user1" was extracted from the `pcap1.pcap` - specific protocol, filters, or data fields examined in Wireshark would be helpful.*
    *   **Answer:** `user1`
    *   **Why is this question relevant?**  Analyzing messaging system activity is important for:
        *   **Communication Analysis:**  Understanding who is communicating with whom, the content of communications, and the timing of messages.
        *   **Insider Threat Detection:**  Investigating suspicious communication patterns that might indicate insider threats or unauthorized data sharing.
        *   **Evidence of Coordination:** In some cases, message logs can provide evidence of coordination between attackers or accomplices.

*   **Question 12:** What is the MD5 hash of the file that Ann sent out?
![image](https://github.com/user-attachments/assets/f2fada8c-6436-42e3-b416-aa9346f9a8f4)

    Here we can see that Ann was lured by a girl, took a file from the server and sent it out. That file is named `recipe.docx`.
    *   *(Note: The MD5 hash value of `recipe.docx` would be here if calculated)*
![image](https://github.com/user-attachments/assets/59cd71e2-617b-47d8-85bd-12f06f671e6e)

    *   **Step 1: Identify File Transfer in Network Capture:** Analyze `pcap1.pcap` (or related network capture if it's a different one) to identify network traffic related to Ann sending a file. The question mentions "file that Ann sent out" and "recipe.docx".  The image indicates the file name `recipe.docx`.  *Again, more detail is needed on *how* `recipe.docx` was identified in the network capture. Protocol, filters, or specific data fields would be helpful.*
    *   **Step 2: Export the File (if possible):** If the file `recipe.docx` was transmitted over the network in a way that allows for file extraction from the network capture (e.g., through HTTP file upload, FTP data transfer, or a file transfer protocol within the messaging system), export the file from Wireshark.
    *   **Step 3: Calculate MD5 Hash:** Calculate the MD5 hash of the exported `recipe.docx` file using tools like `Get-FileHash` (PowerShell), `md5sum` (Linux/macOS), or online MD5 calculators. *The MD5 hash value should be recorded here.*
    *   **Answer (MD5 Hash):** *(The MD5 hash value of "recipe.docx" would be inserted here after calculation)*
    *   **Why is this question relevant?**  Similar to Question 10, identifying the leaked file and its hash is crucial for:
        *   **Data Breach Assessment:**  Determining what specific file was sent out.
        *   **Content Analysis:** Examining the contents of `recipe.docx` to understand its nature and sensitivity.
        *   **Impact Evaluation:** Assessing the potential impact of leaking this specific file.
        *   **Integrity Verification:** MD5 hash helps verify file integrity if a copy of the original `recipe.docx` exists for comparison.

*   **Question 13:** What is the system timezone?

    Using digital forensics software, view the `web-server-linux-003.ad1` file.
![image](https://github.com/user-attachments/assets/4084cb1a-46d9-453a-b617-362442a85a2e)

    *   **Step 1: Open Image File in Forensic Software:** The question mentions "digital forensics software" and the file `web-server-linux-003.ad1`.  `.ad1` is a common forensic image format (AccessData Disk Image). Use forensic software capable of analyzing `.ad1` images (e.g., Autopsy, EnCase, FTK Imager, X-Ways Forensics). Open the `web-server-linux-003.ad1` image in the chosen software.
    *   **Step 2: Locate System Timezone Information:** Forensic software typically parses system configuration files and metadata from disk images. Look for sections or features within the software that display system information, operating system details, or configuration settings.  In Linux systems, timezone information is often stored in files like `/etc/timezone` or `/etc/localtime`. The image from Autopsy shows "Time Zone: Europe/Brussels" in the "Operating System Information" section.
    *   **Answer:** `Europe/Brussels`
    *   **Why is this question relevant?**  Determining the system timezone is important for:
        *   **Timestamp Correlation:**  Accurately interpreting timestamps from log files, file system metadata, and other artifacts. Timestamps are often recorded in local system time. Knowing the timezone allows you to convert them to a standard timezone (like UTC/GMT) for consistent analysis and correlation across different systems or data sources.
        *   **Event Reconstruction:**  Building accurate timelines of events requires understanding the timezone in which events were recorded.
        *   **Geographic Context (Potentially):**  Timezone can sometimes provide clues about the geographic location of the system or user.

*   **Question 14:** Who was the last user to log in to the system?
![image](https://github.com/user-attachments/assets/8eaf755c-461b-4c42-8902-e538b1cac2d5)

    Extract the `auth.log` file.

    Put it into Kali Linux.
![image](https://github.com/user-attachments/assets/a9803a0e-3bbc-46a5-aa3a-8b6cffc0ab9d)

    Put the "accepted password" (successful login) logs from the file into the `accepted_logins` file.
![image](https://github.com/user-attachments/assets/10def0ca-8770-47f5-a125-524fc4326a58)

    Use the `sort` command to see the last log (last user) successfully logged in, which is root.

    ![image](https://github.com/user-attachments/assets/dade1fdd-37e8-4e3c-859f-e387e14b7c4b)

    *   **Step 1: Extract `auth.log` from Image:** The question refers to `auth.log` and a forensic image (`web-server-linux-003.ad1` implied from Question 13). Extract the `auth.log` file from the `/var/log` directory within the `.ad1` image. You can use forensic software to browse the file system within the image and export the `auth.log` file.
    *   **Step 2: Transfer to Kali Linux (Analysis System):**  Transfer the extracted `auth.log` file to a Kali Linux system (or another Linux system with command-line tools) for easier log analysis.
    *   **Step 3: Filter for Successful Logins:** Filter the `auth.log` file to keep only lines indicating successful logins. The example uses `grep "Accepted password"` to extract lines containing "Accepted password," which is a common log message for successful SSH logins in `auth.log`.  `grep "Accepted password" auth.log > accepted_logins`
    *   **Step 4: Sort Logins Chronologically (Reverse Order):** Sort the filtered login logs chronologically in reverse order (newest to oldest) to find the last login.  The example uses `sort -r accepted_logins`. The `-r` option for `sort` reverses the sorting order.  By sorting in reverse chronological order, the last entry in the sorted output will represent the most recent successful login.
    *   **Step 5: Identify Last User:** Examine the last line in the sorted output. The example shows the last line is related to a root login.
    *   **Answer:** `root`
    *   **Why is this question relevant?**  Identifying the last logged-in user is useful for:
        *   **User Activity Tracking:**  Understanding who was recently active on the system.
        *   **Account Compromise Assessment:** If the last login is by an unexpected user (especially a privileged account like root), it could indicate unauthorized access or account compromise.
        *   **Timeline Context:**  The timestamp of the last login provides a point of reference for building a timeline of events.

*   **Question 15:** How many users have a login shell?
![image](https://github.com/user-attachments/assets/b8e00bf5-9f5a-4e92-b679-91e01a4bc963)

    Extract the `passwd` file from `/etc`.

    Continue to put it into Kali.
![image](https://github.com/user-attachments/assets/acab02a9-79c8-4b8d-91e1-898d4a660ced)

    Use the `awk` command to count how many users in the `passwd` file just put in have a login shell:
    ![image](https://github.com/user-attachments/assets/bd9e216f-bcdc-4968-9d3e-4849725130d6)

    *   **Step 1: Extract `passwd` File:** Extract the `/etc/passwd` file from the `.ad1` image. The `/etc/passwd` file on Linux systems contains user account information.
    *   **Step 2: Transfer to Kali Linux:** Transfer the `passwd` file to Kali Linux.
    *   **Step 3: Use `awk` to Count Login Shells:** Use the `awk` command to process the `passwd` file and count users with a login shell.
        *   `awk -F':' '$7 != "/sbin/nologin" && $7 != "/bin/false" { count++ } END { print count }' passwd`
        *   `-F':'`: Sets the field separator to colon (`:`) because fields in `/etc/passwd` are separated by colons.
        *   `'$7 != "/sbin/nologin" && $7 != "/bin/false"'`: This is the condition. `$7` refers to the 7th field in each line of `/etc/passwd`, which is the login shell field. The condition checks if the login shell is *not* equal to `/sbin/nologin` and *not* equal to `/bin/false`.  Users with `/sbin/nologin` or `/bin/false` as their login shell are typically system accounts or accounts that are not intended for interactive logins.
        *   `{ count++ }`: If the condition is true (the user has a login shell), increment the `count` variable.
        *   `END { print count }`: After processing all lines, print the final value of `count`.
    *   **Answer:** `06` (meaning 6 users have a login shell)
    *   **Why is this question relevant?**  Counting users with login shells helps to:
        *   **User Account Audit:**  Understand the number of interactive user accounts on the system.
        *   **Security Assessment:**  Reduce the attack surface by disabling login shells for system accounts or service accounts that do not require interactive logins.
        *   **Account Management:**  Identify and manage user accounts, ensuring that only necessary accounts have login shells.

*   **Question 16:** Put the logs related to user addition into the `b.txt` file for analysis.
![image](https://github.com/user-attachments/assets/e93232f9-5dff-4ef4-a50f-22570a075c14)
![image](https://github.com/user-attachments/assets/ac3859f2-c67b-4c9e-a81f-8186980f6d38)

    User `vulnosadmin` created user `webmin`.

    This is also displayed in the `bash_history` log of this user.
![image](https://github.com/user-attachments/assets/5660e146-46e3-4b69-a326-76f3dce8c8af)

    *   **Step 1: Identify User Addition Logs:** The question asks for "logs related to user addition".  On Linux systems, user addition events are often logged in files like `auth.log`, `audit.log`, or `syslog`.  The images show `auth.log` being examined.
    *   **Step 2: Filter for User Addition Events:** Filter the `auth.log` (or relevant log file) for events related to user creation commands like `useradd`, `adduser`, or similar commands.  The images show lines from `auth.log` containing `useradd webmin` which indicates the creation of the user "webmin".
    *   **Step 3: Save Filtered Logs to `b.txt`:** Save the filtered log lines to a file named `b.txt` (as requested in the question) for further analysis. `grep "useradd" auth.log > b.txt` (or similar command).
    *   **Step 4: Examine User `vulnosadmin`'s `bash_history`:** The text also mentions checking `bash_history` of user `vulnosadmin`.  `bash_history` files store commands executed by users in their bash shell.  Examine the `bash_history` file for the user `vulnosadmin` (typically located in `/home/vulnosadmin/.bash_history` - you would need to extract this from the image).  The image shows the `bash_history` file of `vulnosadmin` containing the `useradd webmin` command, confirming that user `vulnosadmin` created the user `webmin`.
    *   **Why is this question relevant?**  Analyzing user addition logs and command history helps to:
        *   **Identify Unauthorized Account Creation:** Detect creation of user accounts that were not authorized or are suspicious.
        *   **Attribute Actions to Users:**  Determine which user performed the user creation action (in this case, `vulnosadmin`).
        *   **Understand Post-Compromise Activity:**  User creation is often part of post-compromise activity by attackers to establish persistence or create backdoors.

*   **Question 17:** How many users have sudo access?

    Thus, the users who can use sudo here are: `root`, `php`, `mail`
    *   **Answer:** `3`
    *   **Step:** The question implicitly assumes you've already identified users with sudo access in previous analysis (though the steps aren't explicitly detailed here).  **How to determine sudo access?**  On Linux systems, sudo access is typically controlled by the `/etc/sudoers` file or files in the `/etc/sudoers.d/` directory.  You would need to:
        *   **Extract `/etc/sudoers` and `/etc/sudoers.d/`:** Extract these files/directories from the `.ad1` image.
        *   **Analyze `sudoers` Files:** Examine the contents of `/etc/sudoers` and files in `/etc/sudoers.d/`. These files define sudo rules. Look for lines that grant sudo privileges to users or groups.  Common indicators include lines starting with user or group names followed by `ALL=(ALL:ALL) ALL` (or similar sudo rules).
        *   **Identify Sudo Users:** Based on the `sudoers` file analysis, identify the users who are explicitly granted sudo access. The text lists `root`, `php`, and `mail` as users with sudo access. *More detail would be needed on exactly *how* these users were identified from the `sudoers` configuration.*
    *   **Answer:** `3`
    *   **Why is this question relevant?**  Knowing which users have sudo (superuser) access is critical for security assessment:
        *   **Privilege Management:**  Sudo access grants users elevated privileges to run commands as root.  Limiting sudo access to only necessary users is a key security principle.
        *   **Security Risk Assessment:**  Users with sudo access pose a higher security risk if their accounts are compromised because attackers can gain full control of the system.
        *   **Compliance Auditing:**  Compliance regulations often require organizations to control and audit sudo access.

*   **Question 18:** Which file did the user 'root' delete?

    Go into root's history to see. Here there is an `rm` command, it removes file `37292.c`.
    ![image](https://github.com/user-attachments/assets/37ec87f2-2596-48c5-bfc9-d8fe6a979e9d)
![image](https://github.com/user-attachments/assets/4cd157d5-ca45-4435-8216-0333ab66964f)

    *   **Step 1: Examine Root's `bash_history`:** The question directs you to "root's history".  On Linux, root's command history is typically stored in `/root/.bash_history`.  Extract the `/root/.bash_history` file from the `.ad1` image.
    *   **Step 2: Analyze `bash_history` for `rm` Command:** Examine the contents of `root/.bash_history` file. Look for commands that involve file deletion, specifically the `rm` (remove) command. The images show a line in `root/.bash_history`: `rm 37292.c`.
    *   **Answer:** `37292.c`
    *   **Why is this question relevant?**  Tracking file deletion activity by root (or any user) can be important for:
        *   **Data Tampering Detection:**  Identifying if important files were deleted, potentially to hide evidence or disrupt system operation.
        *   **Understanding User Actions:**  Reconstructing user activity and understanding what files users were working with and potentially removing.
        *   **Malware Analysis:**  Malware might delete files as part of its cleanup or evasion techniques.

*   **Question 19:** What Content Management System (CMS) is installed on the machine?
*   ![image](https://github.com/user-attachments/assets/186dce0d-5c76-4096-b10d-15c61e2de496)

    *   **Step:** The image shows a web browser accessing a URL (`http://192.168.1.103/`).  The text displayed in the browser window is a default page for "Drupal". Drupal is a popular open-source Content Management System (CMS).  Accessing the web server's root directory in a browser often reveals a default CMS page if a CMS is installed.
    *   **Answer:** `Drupal`
    *   **Why is this question relevant?**  Identifying the CMS installed on a web server is important for:
        *   **Vulnerability Assessment:**  Knowing the CMS type and version allows you to research known vulnerabilities associated with that specific CMS. CMS platforms are frequent targets for attackers.
        *   **Attack Surface Mapping:**  CMS platforms often have specific attack vectors and common vulnerabilities that attackers exploit.
        *   **Configuration Review:**  CMS installations require specific configurations.  Reviewing the CMS configuration can reveal security misconfigurations.

*   **Question 20:** What version of CMS is installed on the machine?
*   ![image](https://github.com/user-attachments/assets/2bcccaff-f88f-49fd-876c-78f8f234a9ec)

    *   *(No explicit steps are provided in the original document for this question, and the image provided is the same as for Question 19)*.
    *   **Inferred Step:** To determine the CMS version, you would typically need to:
        *   **Examine CMS Files:**  Look for files within the web server's document root directory that contain version information.  For Drupal, this might be in files like `CHANGELOG.txt`, `README.txt`, or CMS-specific configuration files.
        *   **Access CMS Admin Interface:**  Sometimes the CMS admin login page or the CMS's "About" section will display the version number.
        *   **Use CMS Detection Tools:**  Tools like `whatweb` or online CMS detectors can attempt to automatically identify the CMS version by analyzing website headers, code patterns, and known CMS fingerprints.
    *   **Answer:** *(The answer for the CMS version is missing from the original document. To answer this, further investigation of the Drupal installation would be needed)*
    *   **Why is this question relevant?**  Knowing the *version* of the CMS is even more critical than just knowing the CMS type for:
        *   **Vulnerability Identification:**  Vulnerabilities are often version-specific.  Knowing the exact version allows you to pinpoint known vulnerabilities that affect that particular CMS installation.
        *   **Patching and Remediation:**  Version information is essential for applying the correct security patches and updates to address known vulnerabilities in the CMS.
        *   **Exploit Research:**  Attackers often target known vulnerabilities in specific CMS versions. Version information is necessary for researching and understanding potential exploits.

*   **Question 21:** Which port is listening to receive attack commands from the hacker?
![image](https://github.com/user-attachments/assets/982a13d2-f376-4dfb-8e98-5991b0175482)

    *   *(No explicit steps are provided in the original document for this question, and the image is not directly helpful for answering it)*.
    *   **Inferred Step:** To determine listening ports, you would typically use network tools on the compromised system (if it's live) or analyze system configuration files or memory dumps (if you have an image).  Common methods include:
        *   **`netstat -tulnp` (Linux):**  This command lists listening ports and associated processes.  You would need to execute this command on the compromised system or analyze the output if it was captured.
        *   **`ss -tulnp` (Linux):**  A more modern alternative to `netstat`.
        *   **`tasklist /svc` and `netstat -ano` (Windows):**  Windows equivalents for listing processes and network connections.
        *   **Analyzing Process List from Memory Dump:** If you have a memory dump, memory analysis tools can be used to list listening ports and associated processes.
        *   **Configuration File Review:**  Sometimes configuration files for network services (e.g., SSH, web servers) will specify listening ports.
    *   **Answer:** *(The answer for the listening port is missing from the original document.  To answer this, network analysis or system analysis tools would be needed to identify listening ports. The image provided is not directly relevant to this question.)*
    *   **Why is this question relevant?**  Identifying listening ports, especially unusual or unexpected ports, is important for:
        *   **Malware Detection:**  Malware often opens listening ports for command and control communication or to provide backdoor access.
        *   **Unauthorized Services:**  Unnecessary or unauthorized services listening on open ports increase the attack surface.
        *   **Network Security Assessment:**  Understanding listening ports helps to assess the system's network services and identify potential vulnerabilities.

*   **Question 22:** What is the path to the root directory of the PHP user?
![image](https://github.com/user-attachments/assets/5f8c99d3-8106-4f90-aa21-20f9b00aa569)

    *   *(No explicit steps are provided in the original document for this question, and the image is not directly helpful for answering it)*.
    *   **Inferred Step:** To find the home directory of the "php" user, you would typically consult the `/etc/passwd` file.  As mentioned in Question 15, the `/etc/passwd` file contains user account information.  The 6th field in each line of `/etc/passwd` is the home directory for that user.
        *   **Extract `/etc/passwd` (if not already extracted):** Extract the `/etc/passwd` file from the `.ad1` image.
        *   **Examine `/etc/passwd` for "php" user:**  Open the `/etc/passwd` file and look for the line for the user "php".
        *   **Extract Home Directory Path:**  The 6th field in the "php" user's line will be the path to their home directory. The image seems to indicate the path is `/var/www`.
    *   **Answer:** `/var/www`
    *   **Why is this question relevant?**  Knowing the home directory of a user, especially a system user like "php" (often associated with web servers), is useful for:
        *   **File System Navigation:**  Knowing where to look for user-specific files, configuration, and data.
        *   **Security Auditing:**  Auditing files and permissions within user home directories.
        *   **Understanding Application Context:** For system users like "php", the home directory might be related to the web server's document root or application files.




# Task 1: Create a DD-format Image File

**Objective:** Create a bit-by-bit copy (a "forensic image") of a drive using the `dd` command. This is a **crucial first step** in any digital forensics investigation.  The `dd` command, a standard tool in Linux and other Unix-like systems, is used for low-level data copying. By creating an exact copy, we ensure that all data, including deleted files and unallocated space, is preserved.  This allows examiners to analyze the evidence without risking alteration or damage to the original source. We will use the "dd" format as it's a raw, uncompressed format widely compatible with forensic tools.

![image](https://github.com/user-attachments/assets/9ac2fee2-7629-457e-9d5f-1287ce2ff783)

*   **Step 1: File and Group Permissions (Linux) - *Securing the Evidence File***
    *   Before creating the image file, we set up appropriate file system permissions in Linux. **Why is this important?**  Proper permissions are essential for maintaining the **chain of custody** and ensuring the **integrity** of digital evidence.  By restricting access, we prevent unauthorized modification or viewing of the image file.
    *   We create a dedicated group (e.g., `forensics_group`), add this group to the file we are about to create, assign ownership to a designated forensic user, and set specific access rights (e.g., read and write only for the forensic group, read-only for others if necessary, and no execute permissions).  This granular control limits who can interact with the sensitive data within the image file, ensuring only authorized personnel can access and analyze it.

    ![image](https://github.com/user-attachments/assets/f5dc2132-9029-4bf8-b62e-4319ee676c9f)

*   **Step 2: Samba Configuration (Network Share) - *Facilitating Access and Collaboration***
    *   Samba is configured to create a network share. **Why Samba?**  Samba allows seamless file sharing between Linux/Unix-like systems (like Kali Linux where we might be performing analysis) and Windows systems (which might be the system we are imaging or where other analysts are working). This network share enables us to access the image file (and other related files) from different machines on the network. This is beneficial for:
        *   **Collaboration:** Multiple analysts can access the image from their workstations.
        *   **Tool Access:**  If your specialized forensic analysis tools are located on a different system than where the image is created, a network share provides easy access.
    *   We create a dedicated user (e.g., `forensics_user`), set a Samba password for that user to control access to the share, and crucially, add this user to the dedicated group `nhomdieutra` (meaning "investigation group"). This ensures that only members of the investigation team can access the forensic share.

    ![image](https://github.com/user-attachments/assets/40a3a8a3-ad95-4c89-8518-18d7507082f4)

*   **Step 3: Initial Mapping (Physical Machine) - *Initial Setup Attempt***
    *   We first attempted to map a network drive from a Kali Linux machine (a common distribution used for penetration testing and digital forensics) to the physical machine where the target drive was located.  **Why map to the physical machine initially?**  In some scenarios, you might want to directly image a drive connected to a physical machine from a remote analysis workstation. This step represents a common initial approach.

    ![image](https://github.com/user-attachments/assets/f14ae1e3-56f4-4311-af25-b37ef9986e15)

*   **Step 4: Switch to Virtual Machine - *Addressing Practical Limitations***
    *   Due to the large size of the target drive (500GB), we decided to switch to using a virtual machine. **Why the switch?**  Transferring a 500GB image over a network can be very time-consuming and resource-intensive.  Using a virtual machine, especially if the target drive is also virtualized, offers several advantages:
        *   **Speed:** Data transfer within a virtualized environment is often much faster than over a network.
        *   **Resource Efficiency:**  Reduces network bandwidth usage.
        *   **Isolation:**  Keeps the imaging process isolated within the VM environment.

    ![image](https://github.com/user-attachments/assets/fb2add65-4fda-4c7e-97d5-ba04d6300053)

*   **Step 5: Mapping to Virtual Machine - *Establishing the Analysis Environment***
    *   We successfully mapped the network drive (the Samba share we created) to the virtual machine. This establishes the connection between our Kali Linux analysis VM and the location where we will store the image.

    ![image](https://github.com/user-attachments/assets/9e370bd2-53ef-4cfe-87b5-a71f06c290e8)

*   **Step 6: Identify Target Drive - *Verification is Key***
    *   We carefully identified the target drive as "Drive E" within the virtual machine environment. **Why is this step critical?**  **Incorrectly identifying the target drive can lead to imaging the wrong data, or even worse, overwriting the evidence drive!**  Double-checking and verifying the drive letter, size, and contents is paramount before proceeding with image acquisition. *Best practice would be to use disk management tools within the VM to definitively confirm the correct drive.*

    ![image](https://github.com/user-attachments/assets/b9e04084-3d47-46d9-97f8-f0004c72928d)

*   **Step 7: Image Acquisition (dd) - *Creating the Forensic Copy***
    *   We executed the `dd` command to create the `dd` image. **This is the core action of Task 1.**  **What `dd` command would be used here?**  A typical `dd` command for forensic imaging would look like this:
        ```bash
        sudo dd if=/dev/sdb of=/mnt/share/evidence_image.dd bs=4096 conv=noerror,sync status=progress
        ```
        **Let's break down this command:**
        *   `sudo`:  `dd` often requires root privileges to access raw devices.
        *   `if=/dev/sdb`:  **Input File**.  `/dev/sdb` is assumed to be the device node representing the target "Drive E" in the Linux VM. **Important:**  You *must* verify the correct device node for your target drive in your specific environment (using `lsblk`, `fdisk -l`, etc.).  Incorrect device selection can lead to data loss or imaging the wrong drive.
        *   `of=/mnt/share/evidence_image.dd`: **Output File**.  `/mnt/share/evidence_image.dd` specifies the path and filename where the `dd` image will be saved. `/mnt/share` would be the mount point of our Samba share.  Choose a descriptive filename (e.g., `evidence_image.dd`) and location that is easily accessible.
        *   `bs=4096` (or `bs=4k`): **Block Size**. Sets the block size for reading and writing data.  4096 bytes (4KB) is a common and efficient block size for imaging.
        *   `conv=noerror,sync`: **Conversion Options**.
            *   `noerror`:  Tells `dd` to continue copying even if it encounters read errors on the source drive. This is crucial in forensic imaging as you want to capture as much data as possible, even from potentially damaged drives.  Instead of halting on an error, `dd` will attempt to skip over bad sectors.
            *   `sync`:  Pads each input block with zeros to the specified block size if read errors occur. This ensures that the output image is the exact same size as the input drive, even if there are read errors. This helps maintain sector alignment for later analysis.
        *   `status=progress`: (Optional but highly recommended): Displays a progress bar during the imaging process, allowing you to monitor the progress and estimate completion time.

    *   **Documentation is key:** The exact `dd` command used *should always be documented* in your case notes or lab documentation.  This ensures reproducibility and transparency in your process.

    ![image](https://github.com/user-attachments/assets/d656eba5-dbd2-4d8b-80e2-ece70e4931df)

*   **Step 8: Verification (Kali Linux) - *Confirming Image Creation***
    *   We checked the Kali Linux machine (our analysis VM) to confirm that the image file `evidence_image.dd` was successfully created in the Samba share. This is a basic check to ensure the `dd` command completed without major errors and the image file exists where expected.

    ![image](https://github.com/user-attachments/assets/e2dc0d45-1e38-4fb8-b925-f24515a7ea3c)

*   **Step 9: Integrity Check (MD5 Hash) - *Ensuring Data Integrity***
    *   We calculated the MD5 hash of the newly created image file. **Why calculate an MD5 hash?**  **Data Integrity is paramount in forensics.** The MD5 hash acts as a unique digital fingerprint of the image.
    *   **How does it work?** The MD5 algorithm produces a 128-bit hash value.  If even a single bit in the image file is altered (due to data corruption during transfer, storage, or later analysis), the MD5 hash will change completely.
    *   **Best Practice:** You should also calculate the MD5 hash of the *source drive* *before* imaging (if possible and without altering the source drive). Then, compare the hash of the source drive with the hash of the image file. If they match, you have a high degree of confidence that the image is a bit-perfect copy.
    *   We will store this MD5 hash securely and use it later to verify that the image hasn't been tampered with or corrupted at any point during the analysis process. This is a critical part of maintaining the **chain of custody**.

    ![image](https://github.com/user-attachments/assets/3102fae5-3190-4470-8d7e-30a8733edc74)

# Task 2: Convert the Image File from E01 to DD Format

**Objective:** Convert a forensic image from the EnCase Evidence File format (E01) to the raw `dd` format. **Why convert from E01 to DD?**  E01 is a proprietary format primarily associated with EnCase, a commercial forensic software suite. While E01 has advantages like compression and metadata storage, the raw `dd` format is:
*   **Open Standard:** Universally recognized and supported by a vast array of forensic tools, both commercial and open-source.
*   **Interoperable:**  Ensures compatibility across different forensic platforms and operating systems.
*   **Simpler:**  Easier to work with at a low level if needed.
Converting to `dd` makes the image more versatile and accessible for analysis using a wider range of tools.

*   **Step 1: Transfer E01 File - *Accessing the Source Image***
    *   We copied the `Windows_001.E01` file to the mapped network drive accessible from the Kali Linux machine. This makes the E01 image available within our analysis environment.

    ![image](https://github.com/user-attachments/assets/d7115474-e47a-4cb7-a6df-e4c8994cd6c2)

*   **Step 2: Conversion with `xmount` - *Performing the Format Conversion***
    *   We used the `xmount` utility to convert the E01 file to the `dd` format. **Why `xmount`?**  `xmount` is a powerful command-line tool specifically designed for working with various forensic image formats, including E01 (EnCase Evidence File format - EWF).  `xmount` is versatile because it can:
        *   **Convert image formats:** As we are doing here, from E01 to DD.
        *   **Mount images virtually:**  `xmount` can also create a virtual block device from a forensic image *without* actually converting the entire image to a different format first. This is efficient for read-only access.
    *   The likely command used was something like:  `sudo xmount --in ewf --out dd Windows_001.E01 /mnt/e01_mount` (where `/mnt/e01_mount` is a directory you create beforehand to serve as a mount point for `xmount`'s virtual device).
        *   `sudo`: `xmount` may require root privileges.
        *   `--in ewf`: Specifies that the input format is EnCase Evidence File (EWF), which is the E01 format.
        *   `--out dd`: Specifies that the desired output format is raw `dd`.
        *   `Windows_001.E01`:  The input E01 file.
        *   `/mnt/e01_mount`: The mount point directory.  `xmount` will create a virtual device in this directory that represents the converted DD image *or* a mountable representation of the E01 (depending on the specific `xmount` options used). In this case, because we specified `--out dd`, it performs the conversion.

    ![image](https://github.com/user-attachments/assets/f37c4d3b-473a-4f40-9931-94563d54f090)

# Task 3: Mount the Image File on a Linux Workstation

**Objective:** Mount the `dd` image file as a read-only filesystem to access its contents. **Why mount the image?** Mounting allows us to interact with the file system contained within the image in a structured way, as if it were a live drive. This is essential for:
*   **File System Navigation:**  Browsing directories and files using standard file system commands (like `ls`, `cd`, `file`, `cat`, `cp`).
*   **Data Extraction:**  Copying files and directories from the image to our analysis system.
*   **Tool Compatibility:** Many forensic tools are designed to work with mounted file systems.
Mounting should always be done **read-only** to prevent accidental modification of the evidence image.

*   **Step 1: Examine Mounted Files - *Verifying Mount and Exploring Content***
    *   We checked the contents of the mounted directory (`/mnt/dd`) using commands like `ls -l /mnt/dd` to verify that the image was mounted correctly.  We then started exploring the filesystem to get a general overview of its structure and contents. This initial exploration helps to confirm successful mounting and orient us within the file system.

    ![image](https://github.com/user-attachments/assets/8cbf9276-9bd9-4589-bec8-6ef808223639)
    ![image](https://github.com/user-attachments/assets/53ef2679-1f02-4fb9-b557-b54df49a78cf)
    ![image](https://github.com/user-attachments/assets/603529df-5f00-4e48-8ed3-b607175e183a)

*   **Step 2: MD5 Hashing (Images Directory) - *Extracting and Verifying Specific Data***
    *   We calculated the MD5 hashes of files within the `/mnt/dd/images` directory and saved the results to `yeucaubailab.txt`. **Why hash files within a directory?**  This is an example of targeted data extraction and verification.  Perhaps in a scenario, "images" are of particular interest.  Hashing these files serves multiple purposes:
        *   **Integrity Verification:**  If we later copy these images out of the mounted image for further analysis, we can re-calculate their MD5 hashes and compare them to the saved hashes to ensure they haven't been corrupted during extraction.
        *   **Uniqueness Identification:** MD5 hashes can help identify duplicate files within the "images" directory or across the entire image, which can be useful for deduplication or identifying common files.
        *   **Evidence Documentation:** The `yeucaubailab.txt` file serves as a record of the hashes we calculated, documenting our analysis and findings.
    *   The specific command used was likely something like: `find /mnt/dd/images -type f -print0 | xargs -0 md5sum > yeucaubailab.txt`.

    ![image](https://github.com/user-attachments/assets/a88ecb29-90af-4da0-9d86-91fc4a3e2eb7)
    ![image](https://github.com/user-attachments/assets/ecbe52ef-9a93-4d37-b2e0-5e0acf40fc58)

*   **Step 3: MD5 Hashing (Songs Directory) - *Repeating Data Extraction for Another Category***
    *   We repeated the MD5 hashing process for files in the "Songs" directory. **Why hash "Songs"?** This demonstrates applying the same data extraction and verification technique to a different category of files ("Songs").  This could be because "songs" represent another category of potentially relevant evidence in the investigation.  It showcases the scalability and repeatability of the hashing process.

    ![image](https://github.com/user-attachments/assets/656a2f4d-c805-4a15-a4b0-fe1e144e4be9)

*   **Step 4: Mounting an APFS Image - *Handling Different File Systems***
    *   We mounted another `dd` image file, this one containing an Apple File System (APFS). **Why mount an APFS image?** This step demonstrates the ability to work with different file system types commonly encountered in digital forensics.  APFS is the modern file system used by macOS and iOS. Being able to mount and analyze APFS images is crucial when investigating Apple devices.
    *   The likely command would have been something like:  `sudo mount -t apfs -o ro,loop /path/to/image.dd /mnt/apfs` (where `/mnt/apfs` is a mount point you create beforehand).

    ![image](https://github.com/user-attachments/assets/4e46772b-c242-424f-8853-73d9af7e9948)

*   **Step 5: MD5 Hashing (.fseventsd) - *Analyzing System Metadata***
    *   We calculated the MD5 hash of the `.fseventsd` directory (and likely its contents). **Why focus on `.fseventsd`?**  `.fseventsd` is a directory used by macOS to store file system events.  It's a rich source of metadata and can provide valuable insights into user activity, file access patterns, and system events over time.  Analyzing `.fseventsd` can reveal:
        *   File creation, modification, and deletion timestamps.
        *   Application activity related to file access.
        *   Potentially deleted files or actions that are no longer readily apparent in the regular file system.

    ![image](https://github.com/user-attachments/assets/34056b0c-840f-443b-90ad-b622278c7ed0)
    ![image](https://github.com/user-attachments/assets/97d5345e-a02a-4545-8499-223868d0a24f)

*   **Step 6: Continued Hashing - *Comprehensive Data Verification***
    *   We continued calculating hashes and saving them to a text file, likely for further analysis or reporting.  This suggests a more comprehensive effort to hash a larger portion of the mounted image, potentially for a complete inventory of file hashes or to prepare for deeper analysis.

    ![image](https://github.com/user-attachments/assets/0d503e45-7bfe-4698-b432-7adaf70c0a19)

*   **Step 7: Results - *Presenting Findings***
    *   Displayed the results of the hashing operations, likely in the form of the `yeucaubailab.txt` file or a summary of the hashes calculated.  Presenting results clearly is essential for communication in forensic investigations.

    ![image](https://github.com/user-attachments/assets/2083c720-35a9-4159-b162-4996486d0f99)

# Task 4: Extract Hidden Content from the Hard Drive

**Objective:** Use Python scripts to analyze the image and potentially extract hidden content. **Why extract hidden content?**  Attackers and individuals attempting to conceal illicit activity often try to hide data. This could involve:
*   **Deleted Files:**  Files deleted through normal operating system methods may still be recoverable from unallocated space or file system metadata.
*   **Slack Space:**  Unused space within file system clusters can sometimes contain remnants of previously deleted files.
*   **Steganography:**  Data hidden within seemingly innocuous files (like images or audio files).
*   **Hidden Partitions or Volumes:** Areas of the drive not readily accessible through standard file system navigation.
This task aims to explore techniques for uncovering such hidden data.

*   **Script 1: `Phan_tich_Image.py` (Image_Analysis.py) - *Initial Automated Analysis***
    *   This script likely performs initial automated analysis of the image.  **What might this initial analysis include?** Common tasks for a basic image analysis script could be:
        *   **File System Parsing:** Parsing the Master File Table (MFT) in NTFS or similar structures in other file systems to get a list of files and directories, including metadata.
        *   **Deleted File Identification:**  Searching for remnants of deleted file entries in file system metadata.
        *   **File Type Identification:**  Identifying file types based on file signatures (magic numbers) to categorize files.
        *   **Keyword Searching:**  Searching for specific keywords within the image data.

    ![image](https://github.com/user-attachments/assets/059545f4-ead6-4089-90ef-7c5405166da6)

*   **Script 2: `phan_tich_image_pro.py` (Image_Analysis_Pro.py) - *Advanced Analysis and Feature Enhancement***
    *   This script likely builds upon the first script, adding more advanced features or analysis capabilities. **What "pro" features might be included?**  `phan_tich_image_pro.py` could incorporate:
        *   **Deleted File Recovery:**  Attempting to recover the content of deleted files from unallocated space or file system metadata.
        *   **File Carving:**  Searching raw byte streams for file headers and footers to identify and extract files regardless of file system metadata.
        *   **Signature Analysis:**  More sophisticated file type identification and signature matching.
        *   **Data Visualization:**  Presenting analysis results in a more user-friendly or visual format.

    ![image](https://github.com/user-attachments/assets/106c14e8-a4a7-4f37-9601-e00a7e5a5a6c)
    ![image](https://github.com/user-attachments/assets/63d7b60c-28cc-4333-b029-fcd292809a50)

*   **User Directory Exploration - *Targeted Manual Review***
    *   We manually browsed the home directory of the user "roger," specifically navigating to the "Downloads" directory using a file explorer or command line. **Why focus on the "Downloads" directory?**  The "Downloads" directory is a common location where users store files downloaded from the internet or received via email. It's a prime location to look for:
        *   Malware or suspicious executables.
        *   Documents or files related to illicit activity.
        *   Evidence of user actions.
    Manual review complements automated analysis and can uncover details that scripts might miss.

    ![image](https://github.com/user-attachments/assets/6635d2c1-7026-4636-864b-2a423f3e0664)

*   **Script 3: `phan_tich_image_pro_max.py` (Image_Analysis_Pro_Max.py) - *Maximum Feature Set and Accessibility***
    *   This script likely represents the most advanced version of the analysis tool, potentially incorporating the most comprehensive set of features and aiming for improved usability or accessibility. **What "max" features could be added?** `phan_tich_image_pro_max.py` might include:
        *   **Web Interface:** Providing a web-based interface for interacting with the analysis tool and viewing results, as hinted at by the next step.
        *   **Reporting Capabilities:**  Generating automated reports summarizing findings.
        *   **Advanced Carving Techniques:**  More sophisticated file carving algorithms or support for carving specific file types.
        *   **Integration with other tools:**  Potentially integrating with other forensic tools or databases.

    ![image](https://github.com/user-attachments/assets/5eb9c477-a010-4fdc-a3e7-28a8164d465f)

*   **Web Server Access (host='0.0.0.0') - *Remote Access and User Interface***
    *   The addition of `host='0.0.0.0'` in the `phan_tich_image_pro_max.py` script strongly suggests that a web server was integrated into the script. **Why a web server?** A web interface makes the analysis tool more accessible and user-friendly. Setting the host to `0.0.0.0` makes the server accessible from any network interface on the machine, allowing access from:
        *   **Other computers on the network:**  Analysts can access the tool from their workstations using a web browser.
        *   **The physical machine (if the VM is hosted on it):** As indicated in the description, allowing access from the "physical machine."
    This allows for easier interaction with the results of the analysis, potentially through a web-based dashboard or file browser.

    ![image](https://github.com/user-attachments/assets/7fadfc17-8f71-4031-a182-12a313c9644f)
    ![image](https://github.com/user-attachments/assets/6e114bb2-fe2f-4a6e-ac6a-c4a2dd0eb345)

# Task 5: Analyze the Windows Image File System

**Objective:** Use The Sleuth Kit (TSK) tools (`mmls` and `fsstat`) to examine the low-level structure of the file system within the `Windows_002.dd` image. **Why low-level file system analysis?**  Understanding the file system structure is fundamental to digital forensics. Tools like TSK provide insights that go beyond simply browsing files:
*   **Partitioning Scheme:** `mmls` reveals how the disk is partitioned, which is the foundation upon which file systems are built.
*   **File System Type and Metadata:** `fsstat` provides detailed information about the file system itself, including its type, size, metadata structures, and important offsets.
*   **Metadata Entry Exploration:** Examining specific metadata entries (like the Root Directory, Volume Bitmap, $Secure, $Extend) gives a deeper understanding of how NTFS manages files, security, and extended features.
*   **Inode-level Analysis:**  Working with inodes allows for analysis at a fundamental level, independent of file paths, which can be crucial for recovering deleted files or understanding file system operations.

*   **Step 1: Partition Table Analysis (`mmls`) - *Understanding Disk Layout***
    *   We used the `mmls` command to display the partition table of the `Windows_002.dd` image. **What does `mmls` show us?**  `mmls` (Media Layer Sleuth) analyzes the media layer and shows:
        *   **Partitions:**  Lists each partition defined on the disk image.
        *   **Start and End Sectors:**  Indicates the physical location of each partition on the disk in terms of sectors.
        *   **Size:**  The size of each partition.
        *   **Partition Type:**  Identifies the type of each partition (e.g., NTFS, FAT32, Linux native).
        *   **Description:**  Sometimes provides a descriptive label for the partition.
    This command helps to understand the overall organization of the disk *before* delving into specific file systems. Example: `mmls Windows_002.dd`.

    ![image](https://github.com/user-attachments/assets/1684fac8-6405-4523-8b06-6bea83689b9f)

*   **Step 2: File System Details (`fsstat`) - *File System Metadata Examination***
    *   We used the `fsstat` command to display detailed information about the file system within the `Windows_002.dd` image. **What does `fsstat` reveal?** `fsstat` (File System STATistics) provides file system-specific metadata, including:
        *   **File System Type:** Confirms the file system type (e.g., NTFS, FAT, EXT).
        *   **Volume Label:**  The name assigned to the volume.
        *   **Block Size and Cluster Size:**  Fundamental units of data allocation in the file system.
        *   **Inode Count and Range:**  Information about inodes (file system objects) and their numbering scheme.
        *   **Important Offsets:**  Locations of key metadata structures within the file system (e.g., MFT start in NTFS).
    Example: `fsstat Windows_002.dd`.

    ![image](https://github.com/user-attachments/assets/c9a15a7b-3710-433a-86fb-11bd4bae75bd)

*   **NTFS Metadata Entries - *Key File System Structures***
    *   The following are key metadata entries within the NTFS file system that `fsstat` might identify and that are crucial to understand for NTFS analysis:

        *   **5: Root Directory:**  The top-level directory of the file system.  **Why is the root directory important?** It's the starting point for navigating the entire file system. All other files and directories are ultimately located beneath the root directory.

            ![image](https://github.com/user-attachments/assets/7fd3144f-78cc-4713-92e6-ab5c8f9d0aed)

        *   **6: Volume Bitmap:** A file that tracks which clusters (allocation units) on the volume are in use and which are free. **Why is the Volume Bitmap significant?** It's essential for file system integrity and recovery.  By analyzing the bitmap, you can:
            *   Understand disk space utilization.
            *   Identify unallocated space where deleted files might reside.
            *   Potentially repair file system inconsistencies.

            ![image](https://github.com/user-attachments/assets/ef402b42-d095-4b97-a1e2-85c3c97fa6ed)

        *   **9: $Secure:**  Contains security descriptors for files and directories.  **Why is $Secure relevant to forensics?** It manages Access Control Lists (ACLs) that define permissions for users and groups. Analyzing `$Secure` can reveal:
            *   Who has access to specific files and directories.
            *   Potential unauthorized access attempts or privilege escalations.
            *   Evidence of data exfiltration or tampering based on permission changes.

            ![image](https://github.com/user-attachments/assets/2f72d569-cfde-4e52-9c21-e36f59b4766e)

        *   **11: $Extend:**  A directory that contains other metadata files used to extend the functionality of NTFS, such as `$Quota` (disk quotas), `$ObjId` (object IDs), and `$Reparse` (reparse points). **Why is $Extend of interest?** It houses advanced NTFS features. Analyzing files within `$Extend` can uncover:
            *   Disk quota settings that might be relevant to user activity or data storage limits.
            *   Object IDs that can help track file relationships and history.
            *   Reparse points (like symbolic links or junctions) that could indicate file system manipulation or redirection.

            ![image](https://github.com/user-attachments/assets/646ea15d-fb57-43ac-8439-cc38d315a814)

* **Inode Lookup - *Accessing Files by Inode Number***
    * Find the file name or folder based on the inode number. **Why look up files by inode?** Inode numbers are unique identifiers for file system objects.  In some forensic scenarios, you might know the inode number of a file (e.g., from log files or file system metadata), but not its full path. Inode lookup allows you to:
        *   Locate a file or directory if you only have its inode number.
        *   Access files even if their names or directory structure have been altered.
        *   Work with deleted files that might still have inode entries in file system metadata.
    * **How to do inode lookup with TSK?** You would typically use tools like `istat` (inode status) or `ffind` (find file by inode number) from The Sleuth Kit. The specific command would depend on the file system type and the TSK tools available.  *Example command using `istat` (though `istat` mainly displays inode information, not file names directly):* `istat Windows_002.dd <inode_number>`.  To find filenames associated with inodes, you often need to combine tools and potentially parse output.

    ![image](https://github.com/user-attachments/assets/8015aa79-57a9-4543-bc30-861205008ea2)

*   **File Recovery - *Retrieving Files from the Image***
    *   We recovered files from the image file. **Why file recovery?**  A primary goal of digital forensics is often to recover deleted or lost data.  File recovery techniques aim to:
        *   Retrieve files that have been deleted by the user or operating system.
        *   Recover files from damaged or corrupted file systems.
        *   Extract files that might be hidden or obfuscated.
    *   **How is file recovery done?**  File recovery methods range from simple (undeleting files from the recycle bin) to complex (file carving from unallocated space). In this context, "recovering files from the image" likely refers to using TSK tools like `icat` (inode content access tool) to extract the contents of a file based on its inode number.  *Example `icat` command:* `icat Windows_002.dd <inode_number> > recovered_file.txt`.  Other file recovery tools, both command-line and GUI-based, could also be used depending on the specific recovery needs.

    ![image](https://github.com/user-attachments/assets/984c2c15-37f9-47d5-9e5c-5a40aeae5889)

# Task 6: Create and Analyze a File System Timeline using The Sleuth Kit (TSK)

**Objective:** Create a timeline of file system activity using TSK's `fls` and `mactime` tools. **Why create a file system timeline?** Timelines are invaluable in digital investigations because they:
*   **Chronological Order:**  Organize file system events in chronological order, making it easier to understand the sequence of actions and identify patterns.
*   **Activity Reconstruction:** Help reconstruct user activity, application execution, and system events based on file system timestamps.
*   **Anomaly Detection:**  Enable the detection of unusual or suspicious timestamps that might indicate malicious activity or data manipulation.
*   **Evidence Correlation:**  Facilitate the correlation of file system events with other types of evidence (e.g., event logs, network traffic).

*   **Step 1: Extract Temporal Data (`fls`) - *Gathering File System Timestamps***
    *   We used the `fls` command to extract file system metadata, including timestamps (MAC times - Modification, Access, Change), and write the output to `ado.txt`. **What are MAC times and why are they important?**
        *   **MAC Times:**  Represent three key timestamps associated with files and directories in many file systems:
            *   **Modification Time (Mtime):**  When the file content was last modified.
            *   **Access Time (Atime):**  When the file was last accessed (read or executed).
            *   **Change Time (Ctime):** When file metadata (permissions, ownership, etc.) was last changed.
        *   **Forensic Significance:** MAC times provide a record of file system activity. Analyzing these timestamps can reveal when files were created, accessed, modified, or when system events occurred related to files.
    *   `fls` lists files and directories, including deleted entries (if possible), from a disk image. A likely command would be: `fls -r -m "/" -p Windows_002.dd > ado.txt`.
        *   `-r`:  Recursive, to process all directories and subdirectories.
        *   `-m "/"`:  Mount point. Prepends "/" to file paths in the output, making them absolute paths relative to the root of the mounted image.
        *   `-p`:  Full paths. Displays full pathnames in the output.
        *   `Windows_002.dd`: The input disk image file.
        *   `ado.txt`: The output file where `fls` results are saved (often called a "body file").

    ![image](https://github.com/user-attachments/assets/1437e3db-5915-4b45-a71b-932cb12b065c)
    ![image](https://github.com/user-attachments/assets/a8344012-f94b-40eb-a6fb-c490f165ca10)
    ![image](https://github.com/user-attachments/assets/c70ec20c-4f15-4e9c-b090-22b1fcb86f26)

*   **Step 2: Create Timeline (`mactime`) - *Formatting Temporal Data into a Timeline***
    *   We used the `mactime` command to process the output from `fls` (`ado.txt`) and create a chronological timeline of file system events, saving it to `task4_timeline.txt`. **What does `mactime` do?** `mactime` (MAC time to timeline) takes the "body file" output of `fls` (like `ado.txt`) and:
        *   **Parses MAC times:** Extracts the MAC timestamps from the `fls` output.
        *   **Sorts Chronologically:** Sorts the events by timestamp to create a timeline.
        *   **Formats Output:** Formats the timeline data into a human-readable format, often comma-separated values (CSV) or a similar tabular format.
    *   Example: `mactime -b ado.txt -d > task4_timeline.txt`.
        *   `-b ado.txt`:  Specifies `ado.txt` as the "body file" input.
        *   `-d`:  Specifies delimiter (often defaults to comma, creating CSV-like output).
        *   `task4_timeline.txt`: The output file where the timeline is saved.

    ![image](https://github.com/user-attachments/assets/83587142-b8d2-4937-9243-d461d52cccb6)

*   **Step 3: Timeline Analysis - *Interpreting File System Activity***
    *   We analyzed the `task4_timeline.txt` timeline to understand the sequence of events.  **What to look for in a timeline analysis?**  Key observations from a timeline analysis might include:
        *   **Initial System Creation:**  A cluster of events with very similar timestamps might indicate system installation or creation. The example timeline shows initial creation of NTFS metadata files and directories all around "Thu Dec 19 2019 16:55:24," suggesting a system setup or restore on that date.
        *   **User Activity Patterns:**  Sequences of file accesses, modifications, and creations can reveal user workflows and activities.
        *   **Application Execution:**  File system events related to program files or configuration files can indicate application usage.
        *   **Suspicious Timestamps:**  Timestamps that are inconsistent with normal system operation (e.g., timestamps in the future, timestamps that are abruptly changed) can be indicators of tampering or malicious activity.
        *   **Event Gaps:**  Periods of inactivity in the timeline might also be noteworthy, depending on the context of the investigation.
    *   The timeline helps to visualize the temporal relationships between file system events and allows investigators to focus on time periods of interest.

    ![image](https://github.com/user-attachments/assets/2cf933d3-7885-46f3-91f5-27ba3984a42c)

# Task 7: Analyze Common File Formats using a Hex Editor

**Objective:** Examine the internal structure of files using a hex editor. **Why use a hex editor?**  Hex editors provide a raw, byte-level view of file contents. This is essential for:
*   **File Signature Identification:**  Verifying file types by examining file headers and magic numbers.
*   **Data Carving and Recovery:**  Identifying file fragments or embedded data within files.
*   **Malware Analysis:**  Analyzing the structure of executable files and identifying malicious code patterns.
*   **File Format Understanding:**  Gaining a deeper understanding of how different file formats are structured.
*   **Tampering Detection:**  Identifying subtle modifications or inconsistencies in file structures that might indicate tampering.

*   **Step 1: Analyze "FileMau.docx" (SampleFile.docx) - *DOCX File Structure Examination***
    *   We examined a DOCX file in a hex editor. **What are we looking for in a DOCX file?**  DOCX files are based on the ZIP format and contain XML data. In a hex editor, you would expect to see:
        *   **ZIP Header:**  The "PK" (0x50 0x4B in hexadecimal) file signature at the very beginning of the file. This "PK" signature is the telltale sign of a ZIP archive (and DOCX is essentially a ZIP archive).
        *   **XML Content (within the ZIP archive):**  After the ZIP header, you would see binary data representing the compressed XML files that make up the DOCX document content, styles, metadata, etc.  While the XML itself will be compressed, you can still observe the general structure of the ZIP archive.

    ![image](https://github.com/user-attachments/assets/1c14c739-3336-4201-8642-1c1fae2126f9)

*   **Step 2: Analyze "FileMau.gif" (SampleFile.gif) - *GIF File Structure Examination***
    *   We examined a GIF file in a hex editor. **What are we looking for in a GIF file?**  GIF (Graphics Interchange Format) files have specific headers that identify them as GIF images. In a hex editor, you should look for:
        *   **GIF Header (Magic Number):**  Either "GIF87a" or "GIF89a" at the very beginning of the file (in ASCII representation in the hex editor, which corresponds to hexadecimal values). These headers are the definitive identifiers for GIF files.
        *   **Image Data and Control Blocks:**  Following the header, you'll see binary data representing the image pixels, color palettes, and control blocks that define animation or transparency (if applicable).

    ![image](https://github.com/user-attachments/assets/01f5f036-697a-44f0-8b05-8543d825b0a8)

# Task 8: Collect Volatile Information from a Live Windows System

**Objective:** Use the PsTools suite to gather information from a running Windows system. **Why collect volatile information?**  Volatile data is information that exists only in system memory and is lost when the system is powered off or rebooted.  This includes:
*   **Running Processes:**  Information about currently executing programs and their resource usage.
*   **Network Connections:**  Active network connections and listening ports.
*   **Open Files and Handles:**  Lists of files currently opened by processes and system handles.
*   **Registry Data in Memory:**  Parts of the Windows Registry that are cached in memory.
*   **System Logs in Memory:**  Event logs and other system logs that are actively being written to memory.
Collecting volatile data is crucial in incident response and live forensics because it can capture evidence of:
*   Malware running in memory (that might not be persistent on disk).
*   Active network connections to command-and-control servers.
*   Processes accessing sensitive data.
*   System state at the time of an incident.

*   **PsTools Overview - *Powerful System Administration Utilities***
    *   PsTools is a free collection of command-line utilities from Microsoft Sysinternals. **Why PsTools?**  PsTools are incredibly valuable for system administration, troubleshooting, and, importantly, for incident response and digital forensics on Windows systems. They provide powerful capabilities to:
        *   Gather system information remotely or locally.
        *   Manage processes and services.
        *   Interact with the Windows Registry and event logs.
        *   Perform network diagnostics.
    Many of these tools are designed to be used remotely, which is particularly useful in enterprise environments or incident response scenarios.

    ![image](https://github.com/user-attachments/assets/c77ae841-b488-4c30-a378-23a1e2976cab)

*   **1. PsKill - *Process Termination***
    *   Terminates a running process. **Why use PsKill?** In incident response, `PsKill` is essential for quickly stopping malicious processes.  It allows you to terminate processes:
        *   By name (e.g., `SSH.exe`).
        *   By Process ID (PID) (e.g., 7388).
        *   Remotely on another Windows system (if you have administrative credentials).
    This can help contain an incident, prevent further damage, or disrupt attacker activity.

    ![image](https://github.com/user-attachments/assets/f18dbc40-d2f4-4aa9-a4d7-eaab00e738d8)

    *   Example:  `.\\pskill -t 7388` (kills process with PID 7388)

*   **2. PsList - *Process Listing and System Monitoring***
    *   Lists running processes, similar to Task Manager but with more detailed information. **Why use PsList instead of Task Manager?** `PsList` provides more comprehensive information and is command-line driven, making it suitable for scripting and automated data collection. It can show:
        *   Process IDs (PIDs).
        *   Process names.
        *   CPU and memory usage.
        *   Thread counts.
        *   Start times.
        *   Handles and threads.
        *   And more (with options like `-x` for extended information).
    `PsList` is useful for:
        *   Monitoring system performance.
        *   Identifying resource-intensive processes.
        *   Investigating suspicious processes or unusual activity.
        *   Generating process lists for documentation.

    ![image](https://github.com/user-attachments/assets/d5657972-0698-4d95-b61c-3f4a83a92d49)

    *   Example:  `.\\PsList -x` (shows extended information)

*   **3. PsLogList - *Event Log Examination***
    *   Dumps the contents of event logs. **Why examine event logs?** Windows Event Logs are critical sources of information about system events, security events, application events, and errors.  `PsLogList` allows you to:
        *   View event logs from the command line.
        *   Filter events based on various criteria (log name, source, event ID, time range, etc.).
        *   Export event logs for offline analysis.
        *   Access event logs remotely.
    Analyzing event logs is a fundamental part of incident response and digital forensics to:
        *   Track user activity.
        *   Identify security incidents (login failures, account lockouts, etc.).
        *   Troubleshoot system problems.
        *   Establish a timeline of events.

    ![image](https://github.com/user-attachments/assets/8e1e539a-d425-4623-add6-aa224baf9aef)

    *   Example:  `.\\PsLogList`

*   **4. PsPing - *Network Connectivity Testing***
    *   Performs network connectivity tests, similar to the standard `ping` utility, but with added capabilities. **Why use PsPing instead of regular `ping`?** `PsPing` offers more advanced features for network diagnostics, particularly useful in incident response and network troubleshooting. It can:
        *   Measure latency (round-trip time) like `ping`.
        *   Measure bandwidth.
        *   Test TCP port connectivity (to check if a specific port is open on a remote host).
        *   Perform ICMP, TCP, and UDP pings.
    `PsPing` is valuable for:
        *   Verifying network connectivity to remote systems.
        *   Troubleshooting network issues.
        *   Testing if network services are available on specific ports.
        *   Measuring network performance.

    ![image](https://github.com/user-attachments/assets/01e6420f-4b6d-4e5e-ace2-a7b573c776f3)

# Task 9: Analyze a Windows RAM Image File

**Objective:** Analyze a memory dump (RAM image) from a Windows system using Redline and Volatility. **Why RAM analysis?**  As mentioned in Task 8, RAM (Random Access Memory) contains volatile information that is lost when the system is powered off. RAM analysis is critical for:
*   **Detecting Memory-Resident Malware:**  Many types of malware (rootkits, fileless malware, injected code) operate primarily in memory and may leave little or no trace on the hard drive.
*   **Analyzing Running Processes:** Gaining detailed information about processes at the time of memory capture, including their memory usage, loaded modules, and handles.
*   **Recovering Decrypted Data:**  Sensitive data that is encrypted on disk might be decrypted and present in memory during runtime.
*   **Identifying Kernel-Level Activity:** Examining kernel modules, drivers, and system calls can reveal rootkit activity and low-level system manipulations.
*   **Extracting Network Information:**  Network connections, listening ports, and cached network credentials can be found in memory.

*   **Redline Analysis - *GUI-Based Memory Examination***
    *   Redline is a free memory analysis tool from FireEye/Mandiant. **Why Redline?** Redline is a powerful and user-friendly tool, especially for initial triage and analysis of memory dumps. It offers a graphical interface and pre-built analysis modules that simplify common memory forensics tasks.  Redline excels at:
        *   **Automated Analysis:**  Redline performs automated scans and analysis of memory dumps, highlighting potentially suspicious items.
        *   **User-Friendly Interface:**  Provides a GUI for browsing processes, modules, handles, network connections, and other memory artifacts.
        *   **Indicator Scoring:**  Assigns scores to indicators of compromise (IOCs), helping to prioritize investigation efforts.
        *   **Reporting:** Generates reports summarizing findings.

    *   **1. Driver Modules - *Examining Kernel Extensions***
        *   Lists loaded device drivers. **Why analyze driver modules?** Device drivers operate at the kernel level, giving them privileged access to the system. Malware often uses drivers for:
            *   Rootkit functionality (hiding files, processes, network connections).
            *   Kernel-level control and persistence.
            *   Bypassing security mechanisms.
        *   **Observation:**  `RamCaptureDriver64.SYS` in the Administrator's Downloads folder is *highly* suspicious. **Why is this a red flag?**  A driver with a name suggesting RAM capture functionality located in a user's Downloads directory is highly unusual and indicative of:
            *   Malware:  Malware might install a driver for malicious purposes.
            *   Unauthorized Data Collection:  Someone may have intentionally installed a RAM capture tool, possibly for malicious or unauthorized data exfiltration.
            *   Legitimate Tool Misplaced:  While less likely, it could be a legitimate tool that was improperly placed in the Downloads directory.  Regardless, its presence in Downloads and its name warrant immediate investigation.

        ![image](https://github.com/user-attachments/assets/b95d613e-844d-47e1-a750-4da7c6533d7d)

    *   **2. Handles - *Tracking System Resource Access***
        *   Handles are references to system resources (files, registry keys, etc.). **Why analyze handles?** Analyzing handles can reveal:
            *   What files a process is currently accessing (open files, directories, devices).
            *   Which registry keys a process is reading or modifying.
            *   Active network connections associated with a process.
            *   Other system objects (processes, threads, events) that a process is interacting with.
        *   **Example:** The provided examples show handles to registry keys related to recently run programs (`RunMRU`) and autorun programs (`Run`). **Why are these registry keys important?**
            *   `HKEY_USERS\...\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`:  `RunMRU` (Run Most Recently Used) stores a list of programs executed from the "Run" dialog. Malware might use this to track user activity or as part of its execution process.
            *   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`: The `Run` key is a common location for malware to establish persistence. Programs listed in this key are automatically executed when a user logs in.  Finding entries in the `Run` key associated with unusual or unknown programs is a strong indicator of malware persistence.

        ![image](https://github.com/user-attachments/assets/2a293d7f-23a9-41ce-a6c7-e75f40d8c2eb)
        ![image](https://github.com/user-attachments/assets/cd8ae2a0-e86d-4484-8a2c-0eae495ec03d)
        ![image](https://github.com/user-attachments/assets/c0a69fdc-7a3b-484f-8f91-b864ebef8aee)

    *   **3. Memory Sections - *Process Memory Map***
        *   Memory sections show the different regions of memory used by a process. **Why analyze memory sections?** Examining memory sections can reveal:
            *   Loaded DLLs (Dynamic Link Libraries): DLLs are libraries of code that processes use.  Unusual or unexpected DLLs loaded by a process can be suspicious.
            *   Heap Allocations:  Dynamically allocated memory used by a process.  Large or unusual heap allocations might indicate memory leaks or malicious activity.
            *   Code Sections:  Sections of memory containing executable code.  Analyzing code sections can help identify injected code, shellcode, or other malicious code.
            *   Data Sections:  Sections containing data used by the process.
        *   **Observation:** The analysis of `spoolsv.exe` (a print spooler service) shows that it has been compromised, leading to the creation of other processes (`rundll32.exe`, `cmd.exe`). **Why is `spoolsv.exe` compromise significant?** `spoolsv.exe` is a legitimate Windows service. Malware often targets legitimate processes for process injection to:
            *   Hide its activity by running within a trusted process.
            *   Gain the privileges of the compromised process.
            *   Evade detection by security software that might whitelist legitimate processes.
        *   The child processes `rundll32.exe` and `cmd.exe` spawned from `spoolsv.exe` are also suspicious because they are common tools used by malware for various malicious actions. This process tree relationship is a strong indicator of process injection and potential malware activity.

           ![image](https://github.com/user-attachments/assets/949ad7d1-85b2-4e1d-9ddc-1d8db41c0077)
           ![image](https://github.com/user-attachments/assets/dc9ad625-4155-4548-88d3-0a934a212b28)

    *   **4. Device Tree - *System Hardware Inventory***
        *   Shows the hierarchical relationship of devices connected to the system. **Why analyze the device tree?** The Device Tree provides a structured view of the system's hardware configuration. Analyzing it can help identify:
            *   Unusual or unexpected devices.
            *   Hidden devices that might be used for malicious purposes (e.g., rogue USB devices, hidden network adapters).
            *   Devices that are not properly configured or have driver issues.
            *   Hardware-based rootkits or implants.
        *   **Observation:** "According to section one, a sign of a Drive inserted, and its child process name is RamCAptureDriver."  This likely refers back to the suspicious `RamCaptureDriver64.SYS` driver and suggests that the "Device Tree" analysis might be showing a device associated with this driver, further reinforcing suspicion. *More detail would be needed in the Device Tree section of Redline to fully understand this observation.*

        ![image](https://github.com/user-attachments/assets/ac4c4741-7ad7-428a-b02e-2c3d5fb02691)

    *   **5. Hooks - *System Call Interception***
        *   Hooks are mechanisms that allow a program to intercept and modify the behavior of other programs or the operating system itself. **Why analyze hooks?** Hooks are a powerful technique, but they are also frequently abused by malware. Analyzing hooks can reveal:
            *   Malware that is using hooks to hide its presence (e.g., rootkits hooking system calls to filter output and conceal files or processes).
            *   Keyloggers or data theft malware that are hooking keyboard or network APIs to capture sensitive information.
            *   Process monitoring or manipulation malware that uses hooks to control other applications.
        *   Legitimate uses of hooks exist (e.g., debugging tools, accessibility software), but in a forensic investigation, unusual or unknown hooks warrant careful scrutiny.

        ![image](https://github.com/user-attachments/assets/d909c35c-77f4-461b-be90-612b5e1d75b4)

*   **Volatility Framework - *Command-Line Memory Forensics Powerhouse***
    *   Volatility is a powerful, open-source memory analysis framework. **Why Volatility?** Volatility is a highly regarded and versatile memory forensics tool. Unlike Redline's GUI, Volatility is command-line based and plugin-driven, offering:
        *   **Extensibility:**  Volatility has a vast library of plugins for analyzing various aspects of memory dumps from different operating systems (Windows, Linux, macOS, Android).
        *   **Scriptability:**  Command-line interface allows for scripting and automation of memory analysis tasks.
        *   **Deep Analysis:**  Volatility provides plugins for in-depth analysis of processes, kernel objects, network artifacts, registry data, and much more.
        *   **Cross-Platform:**  Volatility is cross-platform and can be run on Linux, Windows, and macOS.

    *   **1. `memdump` - *Process Memory Extraction***
        *   Extracts the memory space of a specific process. **Why use `memdump`?** `memdump` is useful for:
            *   Isolating a suspicious process for more focused analysis.
            *   Extracting the memory contents of a process for further examination with other tools (e.g., disassemblers, debuggers).
            *   Analyzing the memory of a specific process to identify injected code, configuration data, or sensitive information.
        *   Command Example: `volatility_2.6_win64_standalone.exe -f "E:\\Dieu_tra_so\\Lab4-Resource\\Windows_RAM.mem" --profile=Win2008R2SP0x64 memdump -p 1896 -D "E:\\Dieu_tra_so\\Lab4-Resource\\task2"` (dumps process with PID 1896).
            *   `-f "E:\\Dieu_tra_so\\Lab4-Resource\\Windows_RAM.mem"`: Specifies the memory dump file.
            *   `--profile=Win2008R2SP0x64`:  Specifies the Windows profile for the memory dump.  **Accurate profile selection is critical for Volatility to correctly parse the memory dump.**  You need to know the operating system and service pack of the system from which the memory dump was taken.
            *   `memdump`:  The Volatility plugin to use (process memory dumper).
            *   `-p 1896`:  Specifies the PID of the process to dump (1896 in this example).
            *   `-D "E:\\Dieu_tra_so\\Lab4-Resource\\task2"`:  Specifies the output directory where the process memory dump file will be saved.

         ![image](https://github.com/user-attachments/assets/2889a1a2-a34c-4cb9-86cb-f45fbf4813b9)
         ![image](https://github.com/user-attachments/assets/bef104e5-074c-4e5e-adee-2c5bd41e1a31)

    *   **2. `cmdline` - *Process Command Line Retrieval***
        *   Shows the command line used to launch each process. **Why is the command line important?** The command line used to start a process can provide valuable context and clues about its purpose and origin. It can reveal:
            *   How a process was launched (manually, by a script, automatically at startup).
            *   Command-line arguments passed to the process, which can provide configuration details or indicate malicious intent.
            *   The path to the executable file, which can help verify if it's a legitimate system file or a malicious program.

        ![image](https://github.com/user-attachments/assets/e83df515-8c82-4358-a3e7-7005c6f2b656)

    *   **3. `filescan` - *Memory-Based File Listing***
        *   Scans memory for file objects. **Why `filescan`?** `filescan` can find files that were open in memory, even if:
            *   They have been deleted from the file system.
            *   They are hidden or not readily visible through normal file system browsing.
            *   The file system metadata is corrupted.
        *   `filescan` works by searching for file object structures in memory, which can persist even after files are deleted or unmounted. This can be crucial for recovering evidence of file activity that is no longer present on the disk.

         ![image](https://github.com/user-attachments/assets/eb91fb12-f72d-4010-8025-dae7ba79d94f)

    * **4. `driverscan` - *Memory-Based Driver Listing***
    *    Scans for loaded drivers, and can also reveal hidden drivers. **Why `driverscan`?** Similar to Redline's Driver Modules analysis, `driverscan` in Volatility provides another way to examine loaded drivers in memory. `driverscan` can:
        *   List loaded drivers and their properties.
        *   Potentially detect hidden drivers or rootkit drivers that are attempting to conceal themselves from the operating system.
        *   Provide information about driver load addresses and memory regions.
        *   Supplement Redline's driver analysis or provide driver analysis capabilities when using Volatility independently.

    ![image](https://github.com/user-attachments/assets/9b1a0cc2-f239-4ac0-b17a-69c337adb4b8)

*   **`strings` Command Analysis - *Basic Text Extraction from Raw Memory***
    *   The `strings` command extracts printable strings from a binary file (like a memory dump). **Why use `strings` on a memory dump?** While basic, `strings` can be surprisingly effective for quickly finding human-readable text within raw memory data. This can reveal:
        *   URLs and domain names.
        *   Email addresses.
        *   File paths.
        *   Command-line arguments.
        *   Error messages.
        *   Configuration data.
        *   Potentially even fragments of documents or chat logs.
    `strings` is a quick and easy way to get a first pass at the contents of a memory dump and identify potentially interesting text-based artifacts.
    *   **1. Extract Domain Names - *Identifying Network Destinations***
        *    `strings Windows_RAM.mem | grep -E '\\.(com|net|org)' | sort | uniq`
          This extracts strings that look like domain names ending in .com, .net, or .org. **Why extract domain names?** Domain names found in memory might indicate:
            *   Websites visited by the user.
            *   Communication with command-and-control servers (in malware cases).
            *   Network resources accessed by applications.
            *   Email domains.
        *   `grep -E '\\.(com|net|org)'`:  Uses `grep` (global regular expression print) with extended regular expressions (`-E`) to filter the output of `strings` and keep only lines that match the pattern of a domain name ending in `.com`, `.net`, or `.org`.
        *   `sort | uniq`:  Sorts the output and then uses `uniq` to remove duplicate lines, providing a clean list of unique domain names.

            ![image](https://github.com/user-attachments/assets/4ddf48d8-64ac-4d38-953d-b91bebee70c6)
            ![image](https://github.com/user-attachments/assets/a9dfc65c-5d92-44b5-8c34-989afe0dce51)
            ![image](https://github.com/user-attachments/assets/92648d62-df08-4edc-9090-55eca2ad1391)

    *   **2. Extract Email Addresses - *Identifying Communication Information***
        *   `strings Windows_RAM.mem | grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' | sort | uniq`
          This extracts strings that match the general pattern of email addresses. **Why extract email addresses?** Email addresses found in memory could be:
            *   User email addresses.
            *   Email addresses used by applications or processes.
            *   Email addresses involved in communications (e.g., in email clients or webmail sessions).
            *   Email addresses used by malware for command-and-control or spamming.
        *   `grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'`:  Uses `grep` with a regular expression to filter for strings that match the typical email address format.

            ![image](https://github.com/user-attachments/assets/a1cbd257-11b1-448f-a20f-c08194585ebd)

    *   **3. List Commands (cmd and PowerShell) - *Tracing Command-Line Activity***
        *   `strings Windows_RAM.mem | grep -i "cmd.exe " | sort | uniq` (finds command lines involving `cmd.exe`)
        *   `strings Windows_RAM.mem | grep -i "powershell.exe" | sort | uniq`
            This command searches for strings containing `powershell.exe`. **Why look for `cmd.exe` and `powershell.exe`?** `cmd.exe` (Command Prompt) and `powershell.exe` (PowerShell) are command-line interpreters in Windows.  Commands executed via these interpreters leave traces in memory. Finding command lines related to `cmd.exe` or `powershell.exe` in a memory dump can reveal:
            *   Commands executed by the user or by applications.
            *   Potentially malicious commands executed by malware or attackers.
            *   System administration actions.
        *   `grep -i "cmd.exe "` and `grep -i "powershell.exe"`:  Use `grep` with `-i` (case-insensitive) to find lines containing "cmd.exe " or "powershell.exe". The space after "cmd.exe" helps to reduce false positives by matching command lines rather than just occurrences of "cmd.exe" within other strings.
        *   **Important Note:**  While `strings` can find command lines, it's a basic approach.  For more reliable and structured command-line history recovery from memory dumps, Volatility offers plugins like `cmdline` (as shown earlier) and `consoles` (for recovering console history buffers).

        ![image](https://github.com/user-attachments/assets/7bc44feb-1904-461b-b162-679f0044ae24)

# Task 10: Identify and Investigate FTP Brute Force Attacks using Splunk

**Objective:** Use Splunk, a Security Information and Event Management (SIEM) platform, to analyze logs and identify potential FTP brute-force attacks. **Why use a SIEM for log analysis?** SIEM (Security Information and Event Management) tools like Splunk are designed to:
*   **Centralize Log Collection:**  Collect logs from various sources across an IT environment (servers, firewalls, applications, etc.).
*   **Log Aggregation and Normalization:**  Combine logs from different sources and formats into a unified format for easier analysis.
*   **Real-time Monitoring and Alerting:**  Monitor logs in real-time for security events and generate alerts when suspicious activity is detected.
*   **Security Incident Detection and Response:**  Help security analysts identify, investigate, and respond to security incidents by providing powerful log analysis and search capabilities.
*   **Compliance Reporting:**  Generate reports for compliance and auditing purposes.
Using a SIEM is essential for managing and analyzing the large volumes of log data generated in modern IT environments to detect security threats effectively.

*   **Step 1: Splunk Installation - *Setting up the SIEM Platform***
    *   Successfully installed Splunk. **Why install Splunk?**  Splunk is the chosen SIEM platform for this task. Installation is the prerequisite for using Splunk to analyze logs.  *This step might also involve setting up a Splunk "index" to store the FTP logs and configuring Splunk to ingest logs from the FTP server or log file.*

    ![image](https://github.com/user-attachments/assets/33f6a42c-6d45-4319-b9d8-d5bbe018a427)

*   **Step 2: Log Inspection - *Searching and Analyzing FTP Logs in Splunk***
    *   Checked the logs within Splunk. **What kind of logs are we inspecting?**  We are focusing on FTP server logs. **What are we looking for in FTP logs related to brute force?**  To identify a brute-force attack, you would typically look for patterns like:
        *   **Failed Login Attempts:**  FTP logs record failed login attempts. Look for log entries indicating "Login failed," "Authentication failed," or similar messages.
        *   **Source IP Addresses:** Identify the source IP addresses associated with failed login attempts.
        *   **Frequency of Failures:**  A brute-force attack is characterized by a *high frequency* of failed login attempts from the same source IP within a short timeframe.
        *   **Usernames Attempted:** Examine the usernames being used in failed login attempts. Brute-force attacks often try common usernames (e.g., "admin," "root," "test") or lists of usernames.
    *   **Splunk Search (Example):**  To find brute-force attempts in Splunk, you would use Splunk's Search Processing Language (SPL) to query the ingested FTP logs.  A basic SPL query might look like this:
           ```splunk
           index=ftp_logs sourcetype=ftp "Failed password for user"
           | stats count by client_ip, user
           | where count > 5  // Adjust threshold as needed
           | sort -count
           ```
           **Explanation of SPL query:**
           *   `index=ftp_logs sourcetype=ftp "Failed password for user"`:  Searches within the `ftp_logs` index (you would create this index in Splunk and configure it to ingest your FTP logs), for events with the `sourcetype` "ftp" (you would configure this sourcetype when ingesting logs), and that contain the string "Failed password for user" (or a similar string indicating login failure in your specific FTP logs).
           *   `| stats count by client_ip, user`:  Pipes the results to the `stats` command, which calculates statistics. `count by client_ip, user` counts the number of events for each unique combination of `client_ip` (source IP address) and `user` (username).  You need to ensure that your FTP logs are parsed in Splunk to extract fields like `client_ip` and `user`.
           *   `| where count > 5`:  Filters the results to show only those source IPs and usernames that have more than 5 failed login attempts (you would adjust this threshold depending on your environment and the sensitivity of your system).
           *   `| sort -count`:  Sorts the results in descending order of the `count`, so the source IPs with the most failed login attempts appear at the top.

    ![image](https://github.com/user-attachments/assets/df52e6c8-579f-452e-84cb-39441c840b58)

    * **Analysis (not pictured, but crucial):**  After running the Splunk search, you would analyze the results to identify source IPs with a high number of failed login attempts.  You would then investigate these source IPs further to confirm if they are legitimate users or potential attackers performing a brute-force attack.

# Task 11: Investigate Network Attacks using Kiwi Log Viewer

**Objective:** Use Kiwi Log Viewer, a log management tool, to analyze logs and identify a successful FTP login after a potential brute-force attack. **Why use Kiwi Log Viewer?** Kiwi Log Viewer is a simpler log management tool compared to a full-fledged SIEM like Splunk. It's often used for:
*   **Real-time Log Monitoring:**  Viewing logs in real-time as they are generated.
*   **Log Filtering and Searching:**  Filtering and searching logs based on keywords, time ranges, and other criteria.
*   **Centralized Log Collection (from fewer sources, typically):**  Collecting logs from a smaller number of sources, often within a local network.
*   **Basic Log Analysis:**  Performing basic analysis and visualization of log data.
Kiwi Log Viewer is suitable for smaller environments or for focused log analysis tasks where a full SIEM might be overkill. In this task, it's used to demonstrate log analysis using a different tool than Splunk.

*   **Step 1: Log Analysis (Kiwi Log Viewer) - *Examining FTP Logs in Kiwi***
    *   We examined the logs in Kiwi Log Viewer, focusing on FTP login events. **What logs are we looking at in Kiwi?**  Again, we are analyzing FTP server logs, similar to Task 10.  You would need to configure Kiwi Log Viewer to collect logs from the FTP server or load a log file into Kiwi.

*   **Step 2: Identify Successful Login (Response Code 230) - *Pinpointing Successful Authentication***
    *   We know that a successful FTP login typically results in a response code of 230 ("User logged in"). **Why response code 230?** FTP (File Transfer Protocol) uses numerical response codes to indicate the status of commands and server actions.  Response code 230 is the standard FTP response code for a successful user login.  We searched for log entries in Kiwi Log Viewer containing this response code.
    *   **Correlation is Key:** *Crucially*, in a real investigation, finding a successful login (response code 230) is only *one piece* of the puzzle.  To confirm a successful brute-force attack, you would need to **correlate** this successful login event with:
        *   **Preceding failed login attempts:** Look for failed login attempts (with error response codes like 530 - "Not logged in") from the *same source IP address* in the logs *prior* to the successful login.
        *   **Time proximity:**  The successful login should occur shortly *after* a series of failed attempts, indicating the attacker likely guessed the correct credentials after multiple tries.
        *   **Unusual login time or location:**  Consider if the login time or source IP address of the successful login is unusual or unexpected for the legitimate user account.

    ![image](https://github.com/user-attachments/assets/d3e10753-125d-4c38-b28a-739382c29dcf)

*   **Step 3: Identify Log ID - *Referencing the Event***
    *   We identified log ID 8622 as corresponding to the successful login after the brute-force attack. **Why note the Log ID?**  Log IDs are unique identifiers assigned to each log event by Kiwi Log Viewer (or other log management systems).  Noting the Log ID (8622 in this case) allows you to:
        *   **Easily reference this specific event later.**
        *   **Quickly locate the event in the logs if you need to re-examine it.**
        *   **Use the Log ID in reports or documentation to precisely identify the event of interest.**

    ![image](https://github.com/user-attachments/assets/95dae9df-ca2a-4abb-ba7e-54868049090c)

# Thank
</details>
