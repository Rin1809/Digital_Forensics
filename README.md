<details>

<summary><h1>This repository, no coding. As a student learning about cyber security, i just want to show what i did and how digital forensics work (doing realistic simulation lab ). If care about it so expan it down ᓚᘏᗢ </h1></summary>

# Digital_Forensics

![image](https://github.com/user-attachments/assets/da81535d-c9e2-4d72-a2eb-6c07bf2e6f52)

This repository documents a series of digital forensics exercises performed in a simulated lab environment.  Each task demonstrates a key aspect of a digital forensics investigation, from image acquisition to memory analysis.  The goal is to provide a practical, hands-on understanding of the tools and techniques used in real-world digital forensics investigations.

# Task 0: Initial File Analysis and Question Answering - Unveiling Hidden Clues

![image](https://github.com/user-attachments/assets/5fa1670e-5425-420a-b8da-8f55f65804cb)

**Objective:** This task serves as an introductory exercise to familiarize you with basic digital forensics techniques. You will be analyzing a provided file, likely containing encoded or hidden information related to a simulated investigation. The goal is to decode this information, answer specific questions based on the extracted data, and understand how seemingly simple tasks can reveal crucial clues in a digital forensics scenario.  This task emphasizes the importance of observation, decoding, and targeted analysis as foundational skills for digital investigations.

## Understanding Hexadecimal Data

Opening the initial file reveals a section of data recorded in hexadecimal format. **Why is data sometimes in hex?** Hexadecimal (base-16) is a common way to represent binary data in a human-readable format. Computers work with binary (0s and 1s), but hex is more compact and easier for humans to read and write than long strings of binary digits.  In forensics, hex representation is often used for:

*   **Examining raw data:** Viewing the exact bytes of a file or disk image, allowing for a granular level of inspection.
*   **Identifying file signatures (Magic Numbers):**  Recognizing file types by their header bytes (often viewed in hex), which is critical for file identification and validation.
*   **Analyzing network packets:**  Looking at the byte-level structure of network communication, essential for protocol analysis and anomaly detection.
*   **Debugging and reverse engineering:**  Understanding the low-level workings of software, necessary for malware analysis and vulnerability research.

## Step 1: Decoding Hexadecimal Data to ASCII - Making Data Readable

To understand the hex data, we need to convert it to a more readable format, typically ASCII text. ASCII (American Standard Code for Information Interchange) is a character encoding standard that represents text in computers.  Converting to ASCII allows us to read and interpret the intended message or information hidden within the hex code.

**How to Convert Hex to ASCII:**

*   **Online Hex to ASCII Converters:** Numerous online tools are available (just search for "hex to ascii converter"). You can copy and paste the hex data into these tools to get the ASCII output quickly and easily.
*   **Command-line Tools (Linux/macOS):**  You can use tools like `xxd -r -p` or `echo "hex_data" | xxd -r -p | strings` in a terminal. These are efficient for batch conversions and scripting.
*   **Hex Editors:**  Hex editors often have built-in functionality to interpret hex data as ASCII or other character encodings, providing a visual representation within the editor itself.

After converting the hex format, the data can be decoded into ASCII for reading. This reveals human-readable text, which is much easier to analyze and from which we can extract the answers to our investigative questions.

![image](https://github.com/user-attachments/assets/8c8f64f9-cc5e-4256-82ec-51012e891b51)

Now we can proceed to answer the specific questions based on this decoded ASCII text.

---

## Question 1:  Identify the Chat Software Website

**Question:** What is the website address of the chat software that the user "Nhung" used?

![image](https://github.com/user-attachments/assets/a11d8035-010c-4b69-836b-ad79d44ffc9e)

**Steps:**

1.  **Examine the Decoded ASCII Text for Web Addresses.** Carefully read through the decoded ASCII text.  Look for strings that resemble web addresses or URLs.  Common patterns to look for include "www.", "http://", "https://", and top-level domains like ".com", ".org", ".net", ".co", etc.
    *   **Rationale:** Websites are often key communication channels. Identifying a chat software website provides context to the user's online activities and potential communication avenues.
2.  **Locate the Website Address.** In the decoded text, identify the line "Website chat cua Nhung la: www.e-chat.co". This clearly indicates the website address.
    *   **Rationale:** Pinpointing the exact website address allows for direct access and further investigation of the chat platform itself, if needed.

**Answer:** `www.e-chat.co`

**Relevance to Digital Forensics:**  Identifying the chat software used can be important for several reasons:

*   **Contextual Understanding:** It provides context about Nhung's online activities and preferred communication platforms.
*   **Further Investigation Potential:** Knowing the specific chat software might enable investigators to explore potential chat logs, account information, or known vulnerabilities associated with that platform.
*   **Link Analysis Starting Point:**  It can serve as a starting point for link analysis, especially if the chat software is known to be associated with illicit activities or threat actors.

---

## Question 2: Determine the USB Drive Hiding Location

**Question:** Based on the decoded text, describe the location where Nhung hid the USB drive.  Answer in Vietnamese without accents, as it might appear in an investigation report.

![image](https://github.com/user-attachments/assets/8e7548ef-c3ec-4426-8d23-0ad2ff520f19)

**Steps:**

1.  **Search for Location Keywords in Decoded Text.**  Carefully read the decoded ASCII text, specifically looking for keywords or phrases that suggest a physical location or hiding place.  Keywords to consider might include "place", "location", "hidden", "giấu" (Vietnamese for "hide"), "nơi" (Vietnamese for "place"), and prepositions indicating location (e.g., "in", "under", "behind", "trong" - Vietnamese for "in").
    *   **Rationale:** In many investigations, physical evidence is crucial. Identifying a potential hiding location from digital clues can directly lead to the recovery of physical evidence.
2.  **Locate the Hiding Place Description.**  In the decoded text, identify the line "Noi Nhung giau USB la: chau cay". This translates to "The place Nhung hid the USB is: flower pot".
    *   **Rationale:**  This directly provides the hiding location described in the text, which is the target of this question.

**Answer:** `chau cay` (meaning "flower pot" in Vietnamese)

**Relevance to Digital Forensics:** Knowing the hiding location of physical evidence (like a USB drive) is crucial for:

*   **Physical Evidence Recovery:**  Providing investigators with a direct lead to the potential physical location of the USB drive, enabling its physical recovery.
*   **Evidence Corroboration:**  Potentially confirming details obtained from other sources (e.g., witness statements, digital logs) with tangible physical evidence.
*   **Understanding Intent:**  The nature of the hiding place itself might provide further clues about the individual's intent to conceal information or activity.

---

## Question 3: Identify the System Attack Method

**Question:** Based on the provided information and log analysis context, what method did the attacker likely use to attempt to compromise the system?

![image](https://github.com/user-attachments/assets/9b227fe3-e5d0-47a6-ba85-216a2f8b1d7a)


**Steps:**

1.  **Analyze Log Snippets for Authentication Failures.** Examine the provided images of log entries, particularly noting any recurring patterns or keywords related to authentication. Look for messages indicating failed login attempts, invalid usernames, or password failures. The images show log entries from `auth.log` with messages like "Failed password for invalid user" and repeated failed authentication attempts.
    *   **Rationale:** Authentication logs are primary sources of information regarding login attempts, both successful and failed. Analyzing failure patterns is key to identifying potential attacks targeting user accounts.
2.  **Recognize Brute-Force Attack Indicators.** Identify the characteristics of a brute-force attack within the log snippets.  Key indicators include:
    *   **High Volume of Failed Logins:** Numerous failed login attempts in a short period.
    *   **Invalid Usernames (Sometimes):** Attempts to log in with usernames that don't exist on the system (as seen in "invalid user").
    *   **Repetitive Nature:**  The attempts often originate from the same or a limited set of source IP addresses.
    *   **System Resource Consumption:** Brute-force attacks can consume system resources due to repeated authentication processes.
    *   **Contextual Clues (from Question):** The question itself hints at "continuous and unusual failed login attempts" and "Burt-Force" (likely a typo for "Brute-Force").
    *   **Rationale:** Recognizing brute-force indicators helps classify the type of attack and understand the attacker's initial access strategy.
3.  **Conclude the Attack Method.** Based on the repeated failed login attempts, especially "Failed password for invalid user," and the question's hint, conclude that the attacker likely employed a brute-force attack.
    *   **Rationale:**  Correctly identifying the attack method is essential for effective incident response and implementing appropriate security countermeasures.

**Answer:** `Brute-Force`

**Relevance to Digital Forensics:** Identifying the attack method is fundamental in incident response and forensics because it allows for:

*   **Understanding Attack Vectors:** Knowing the attack method helps understand *how* the attacker attempted to gain access to the system.
*   **Assessing Potential Damage:** The attack method informs the potential scope of compromise. A successful brute-force attack can lead to unauthorized access, account compromise, and further malicious activities.
*   **Implementing Remediation and Prevention:**  Knowing the attack method is crucial for implementing appropriate security measures to prevent future attacks of the same type (e.g., strengthening passwords, implementing account lockout policies, enabling multi-factor authentication, deploying intrusion detection systems).

---

## Question 4: Determine the Number of Attacking IPs and Successful Compromises

**Question:** How many unique IP addresses were involved in the brute-force attack attempts? Of these, how many IP addresses were associated with *successful* logins?

Based on classifying these IP addresses, they appear to be targets of brute force, based on the high number of login attempts associated with them (limited to the April attack period).

![image](https://github.com/user-attachments/assets/c8aebcf7-a761-4bfe-b2a9-7b0a84a3609f)

**Steps:**

1.  **Count Unique Attacking IPs.** Examine the provided list of IP addresses associated with failed login attempts during the brute-force attack period (April). Count the number of *unique* IP addresses in this list. The provided text indicates "24 unique IP addresses" were involved in failed attempts.
    *   **Rationale:** Counting unique attacking IPs helps quantify the scale of the brute-force attack and identify the potential number of attacker origins.
2.  **Identify IPs with Successful Logins.** Review the subsequent data provided, which lists IP addresses associated with "successful logins (Accept)".  Compare this list to the list of attacking IPs from Step 1. Identify which IPs from the brute-force attempt list also appear in the list of successful logins. The provided text states "6 IPs are listed with successful logins".
    *   **Rationale:** Identifying IPs with successful logins is critical because these represent actual account compromises. These IPs should be prioritized for further investigation and potential blocking.

**Answer (Number of Attacking IPs):** `24`

**Answer (Number of IPs with Successful Attacks):** `6`

**Relevance to Digital Forensics:**  Identifying attacking and successful IPs is important for:

*   **Assessing Scope of Attack:**  Understanding the scale of the brute-force attempt and how many potential entry points were compromised.
*   **Attribution (Initial Tracing):** IP addresses provide initial clues for tracing the attacker's origin, although IP addresses can be spoofed or originate from compromised systems.
*   **Blocking and Mitigation:** IP addresses of attackers can be used to implement immediate blocking measures (e.g., firewall rules, intrusion prevention systems) to prevent further malicious activity from those sources.
*   **Prioritization for Investigation:** IPs associated with successful logins are of higher priority for further investigation as they represent confirmed compromises and potential points of entry for subsequent malicious actions.

---

## Question 5: Determine Newly Created User Accounts During the Attack

**Question:** Which user accounts were newly created on the system *during* the timeframe of the identified brute-force attack?

![image](https://github.com/user-attachments/assets/6c84b070-126f-490e-9f91-0fbd144269f5)

**Steps:**

1.  **Examine Logs for User Creation Events.** Analyze system logs (like `auth.log`, `audit.log`, or `syslog`) for events indicating user account creation. Look for log entries containing commands such as `useradd`, `adduser`, or similar user management commands. The provided image shows `auth.log` entries containing `useradd` commands.
    *   **Rationale:** User creation events are logged for auditing and security purposes. Examining these logs helps track account management actions on the system.
2.  **Identify Usernames Created During the Attack Period.**  Filter the user creation logs to isolate user accounts created *specifically* around the time of the brute-force attack (April, as indicated in the context). In the provided image and text, the users `packet`, `wind3str0y`, `fido`, and `dhg` are identified as being created during the attack timeframe. Distinguish these from pre-existing users like `user1`, `user2`, and `user4`.
    *   **Rationale:** New user accounts created *after* a compromise are highly suspicious. Attackers often create backdoors or accounts for persistence.

**Answer:** `packet`, `wind3str0y`, `fido`, `dhg`

**Relevance to Digital Forensics:**  Identifying newly created user accounts during an attack is a strong indicator of malicious post-exploitation activity because:

*   **Backdoor Establishment:** Attackers frequently create new user accounts as backdoors to maintain persistent access to the compromised system, even if the initial vulnerability is patched.
*   **Persistence Mechanism:** Newly created accounts can be used to regain access if the attacker loses their initial foothold or if their initial access method is detected and blocked.
*   **Privilege Escalation Preparation:**  Attackers might create new accounts to facilitate privilege escalation attempts or to perform actions under a different user context, potentially bypassing access controls.
*   **Confirmation of Account Compromise:** User creation often follows a successful initial compromise (like a brute-force attack), confirming that the attacker gained access and then proceeded to further compromise the system by creating new accounts.

---

## Question 6: Identify the System Scanning Tool Installed by the Attacker

**Question:** What system scanning tool did the attacker install on this compromised Linux Server?

![image](https://github.com/user-attachments/assets/c22e76ce-fdaa-4110-a6fd-1e617e524296)

**Steps:**

1.  **Examine Terminal or Command History Logs.** Analyze terminal logs or command history files (like `.bash_history`, command logs, or terminal logs) for commands related to software installation or system utilities. The image shows a `term.log` file, presumably containing terminal command history.
    *   **Rationale:** Terminal history logs record commands executed by users, providing a direct record of actions taken on the command line, including software installations.
2.  **Look for Package Installation Commands.**  Within the terminal logs, search for commands associated with package managers used for software installation on Linux systems. Common package manager commands include `apt-get install` (Debian/Ubuntu), `yum install` (CentOS/RHEL), `pacman -S` (Arch Linux), etc.  The image clearly shows the command `apt-get install nmap`.
    *   **Rationale:** Package manager commands directly indicate software installation attempts. Identifying these commands reveals what software the attacker tried to install.
3.  **Identify the Installed Tool.** From the identified package installation command (`apt-get install nmap`), determine the name of the tool being installed. In this case, it is `nmap`. Recognize that `nmap` is a well-known and widely used network scanning tool.
    *   **Rationale:** Knowing the specific tool installed provides insights into the attacker's post-exploitation activities and objectives.

**Answer:** `Nmap`

**Relevance to Digital Forensics:**  Identifying installed tools, especially security or network scanning tools, can reveal the attacker's post-exploitation reconnaissance and lateral movement activities because:

*   **Network Reconnaissance:** `Nmap` is primarily used for network reconnaissance. Its installation indicates the attacker was likely scanning the compromised system's network or internal network to map network topology, identify open ports, and discover running services. This information is used for further attack planning.
*   **Lateral Movement Preparation:**  Network scanning is often a precursor to lateral movement. Attackers use scan results to identify other vulnerable systems on the internal network that they can then target to expand their compromise.
*   **Information Gathering:**  Scanning tools help attackers gather detailed information about the target system's configuration, security posture, and potential vulnerabilities. This information aids in planning further attacks and exploitation.

---

## Question 7: Recover Twitter Account Credentials Used for Data Exfiltration

**Question:** The attacker used the social network Twitter to send images from the compromised computer. Identify the account username and password that the attacker used to log in to Twitter.

![image](https://github.com/user-attachments/assets/64ae2c74-a2bf-4b4c-b540-9a1c78f90155)

In file number 3, there is a capture with the host `twitter.com`. When opened, we can see its Authorization hash, in base64 format.  When decoded:

![image](https://github.com/user-attachments/assets/8ba08790-3edf-4089-afd5-80ed9fe0e2a4)
![image](https://github.com/user-attachments/assets/17779deb-8a9f-4dcd-b96f-d1a1b26071c7)

**Steps:**

1.  **Identify Network Capture File and Twitter Traffic.** The question refers to "file number 3" and "twitter.com", suggesting analysis of a network capture file (like a `.pcap` file) for Twitter-related network traffic. Open the network capture file (file number 3, presumably) in a network protocol analyzer like Wireshark and filter for traffic to or from `twitter.com`.
    *   **Rationale:** Network captures record network communication, potentially including credentials transmitted over the network. Filtering for Twitter traffic focuses the analysis on relevant communication related to the question.
2.  **Examine HTTP Requests for Authorization Headers.** Look for HTTP requests within the Twitter traffic. Examine the headers of these HTTP requests for "Authorization" headers.  Authorization headers are commonly used in web authentication to transmit credentials or tokens.
    *   **Rationale:** Authentication credentials for web services are often transmitted in Authorization headers. Identifying these headers within Twitter traffic is a key step towards recovering potential login credentials.
3.  **Identify Base64 Encoded Authorization Value.** The text mentions "Authorization hash, in base64 format".  Locate the value of the "Authorization" header in the Wireshark capture. Recognize that Base64 is a common encoding scheme.
    *   **Rationale:** Base64 encoding is frequently used to encode binary data or credentials for transmission over text-based protocols like HTTP. Recognizing Base64 encoding is crucial for decoding the potentially hidden credentials.
4.  **Decode Base64 Value to Recover Credentials.** Decode the Base64-encoded value from the Authorization header to reveal the original data. Use a Base64 decoder (online tools, command-line tools like `base64 -d`, or programming languages). The decoded output, as shown in the images, reveals "userforlab:passforlab", which is likely the username and password separated by a colon.
    *   **Rationale:** Base64 decoding reverses the encoding process, revealing the original data, which in this case, are the likely Twitter login credentials.

**Answer (Account):** `userforlab`

**Answer (Password):** `passforlab`

**Relevance to Digital Forensics:**  Identifying compromised social media accounts used by attackers is important because:

*   **Data Exfiltration Channel:** Social media platforms can be exploited as channels for exfiltrating stolen data from a compromised system. Attackers might use social media to send data out of the network, bypassing traditional data loss prevention measures.
*   **Command and Control (C2) Potential:** In some sophisticated attacks, social media accounts can be used for covert command and control communication with malware.
*   **Attribution and Tracking Clues:** Social media accounts can provide further clues for tracing the attacker's identity, online presence, or activities outside the immediate compromised system.
*   **Account Remediation Necessity:**  Compromised social media accounts must be immediately secured (passwords changed, accounts potentially suspended or monitored) to prevent further misuse by the attacker, such as spreading misinformation, conducting phishing attacks, or further data exfiltration.

---

## Question 8: Determine Attacker's Internal Network IP Address during FTP Account Theft

**Question:** The attacker connected to the internal network and stole the FTP account credentials of a user within the company. Analyze the network capture file (presumably using Wireshark) to identify the attacker's IP address *within the internal network*.

After using Wireshark:

![image](https://github.com/user-attachments/assets/0498cfd5-f6dd-46e1-bb8b-86ca881a0be9)

**Steps:**

1.  **Analyze Network Capture for FTP Traffic.** Open the relevant network capture file (likely a `.pcap` file) in Wireshark and filter the capture to focus on FTP (File Transfer Protocol) traffic. Apply a filter like `ftp` or `port 21` in Wireshark to isolate FTP communication.
    *   **Rationale:** The question explicitly states that the attacker stole FTP credentials, so focusing on FTP traffic is the most direct approach to finding the attacker's network activity related to FTP.
2.  **Examine FTP Command Sequence for Client IP.** Analyze the sequence of FTP commands within the capture. Look for typical FTP client commands like `USER`, `PASS`, `SYST`, `PORT`, `LIST`, `RETR`, `QUIT`, etc., which indicate an FTP client initiating a connection and interacting with an FTP server. Identify the source IP address of these FTP client commands.  The image highlights FTP commands and points to `192.168.0.117` as the source IP.
    *   **Rationale:** FTP commands are initiated by the FTP client (in this case, the attacker's machine). The source IP address of these commands will reveal the IP address of the machine acting as the FTP client, which is likely the attacker's system within the internal network.

**Answer:** `192.168.0.117`

**Relevance to Digital Forensics:**  Identifying the attacker's IP address within the internal network is crucial for:

*   **Internal Network Mapping:**  Understanding the attacker's location and movement *within* the internal network.  This helps map the attacker's path and identify potentially compromised internal systems.
*   **Identifying Compromised Internal Systems:** The attacker's IP address might be associated with a compromised internal workstation or server that was used as a staging point for further attacks, including the FTP account theft.
*   **Network Segmentation and Security Enhancement:** This information can inform network segmentation strategies and security controls to limit lateral movement of attackers and contain future breaches more effectively. It highlights internal network vulnerabilities that allowed the attacker to operate within the network.

---

## Question 9: Recover Stolen FTP Account Credentials

**Question:** What are the specific username and password of the FTP account that the attacker successfully stole?

After using Wireshark:

![image](https://github.com/user-attachments/assets/49253270-a360-473b-a8f2-d66b1d394b5f)

**Steps:**

1.  **Continue Analyzing Wireshark FTP Traffic.**  Re-examine the Wireshark capture filtered for FTP traffic (from Question 8). Focus on the FTP command stream initiated by the attacker's IP address (identified in Question 8).
    *   **Rationale:** We already know the attack involves FTP account theft, and we've identified the attacker's IP interacting with FTP.  The next step is to find the credential exchange within this traffic.
2.  **Look for USER and PASS Commands.** Within the FTP command stream, specifically look for the `USER` and `PASS` commands.  These are the standard FTP commands used to transmit the username and password during the authentication process.  Note that in basic FTP, these commands transmit credentials in *plain text*. The image highlights the `USER ketoan` and `PASS ispace` commands.
    *   **Rationale:** The `USER` and `PASS` commands are the direct carriers of the FTP username and password. Identifying and examining these commands is the most direct way to recover the stolen credentials from a network capture of FTP traffic.
3.  **Extract Username and Password from Commands.** Extract the username from the `USER` command (e.g., `ketoan` in `USER ketoan`) and the password from the `PASS` command (e.g., `ispace` in `PASS ispace`).
    *   **Rationale:** Extracting the username and password values from the `USER` and `PASS` commands provides the specific stolen FTP credentials, answering the question directly.

**Answer (Account):** `ketoan`

**Answer (Password):** `ispace`

**Relevance to Digital Forensics:**  Identifying stolen credentials (like FTP accounts) is critical because:

*   **Unauthorized Access Confirmation:** Recovering the stolen credentials confirms that the attacker successfully compromised an FTP account and obtained valid login information.
*   **Data Breach Potential:** Stolen FTP credentials can be immediately misused to gain unauthorized access to sensitive file servers and data stored on those servers. This can lead to data breaches, data theft, or malware uploads.
*   **Account Remediation Imperative:**  The compromised FTP account (`ketoan`) must have its password reset *immediately* and potentially be locked down to prevent further misuse by the attacker.  All accounts using the same or similar passwords should also be reviewed and strengthened.
*   **Highlighting Security Vulnerabilities:** The plain-text transmission of FTP credentials underscores a significant security vulnerability (using unencrypted FTP). This finding highlights the urgent need to address insecure protocols and enforce encrypted alternatives (like SFTP or FTPS) to protect sensitive information in transit.  This finding can drive security policy updates and infrastructure improvements.

---

## Question 10: Identify the Leaked File and Calculate its MD5 Hash

**Question:** What is the name of the specific file that was leaked when the attacker exploited the compromised FTP account?  Furthermore, determine and record the MD5 hash of that leaked file.

![image](https://github.com/user-attachments/assets/9966e278-20e5-49b9-88ea-9137a1ee62d5)

Proceed to export a target file from Wireshark.

Using the `Get-FileHash` command on PowerShell, we can calculate the MD5 hash of the newly exported file, which is "file-mat.docx".

![image](https://github.com/user-attachments/assets/949bd198-481e-4a66-b4c1-243ed343abb5)

**Steps:**

1.  **Analyze Wireshark FTP Traffic for Data Retrieval Command.** Continue examining the Wireshark capture filtered for FTP traffic. Look for FTP commands that indicate data retrieval or file download from the FTP server to the attacker's machine.  The `RETR` (retrieve) command is the standard FTP command for downloading a file. The image shows a `RETR file-mat.docx` command.
    *   **Rationale:** The `RETR` command directly indicates file download activity in FTP. Identifying this command reveals which file was downloaded by the attacker using the compromised FTP account.
2.  **Identify the File Name from RETR Command.** Extract the file name from the `RETR` command. In the example, the file name is `file-mat.docx` (from `RETR file-mat.docx`).
    *   **Rationale:** Extracting the file name directly answers the first part of the question: identifying the specific file that was leaked.
3.  **Export the File Content from Wireshark.** Wireshark allows you to export the actual data payload of network streams, including files transferred via FTP. In Wireshark, locate a packet within the FTP data transfer stream related to the `RETR file-mat.docx` command. Right-click on this packet and use options like "Follow TCP Stream" or "Export Objects" (depending on Wireshark version and FTP stream structure) to export the file content as `file-mat.docx`.
    *   **Rationale:** Exporting the file from Wireshark allows us to obtain a copy of the *actual* leaked file for further analysis, content review, and integrity verification.
4.  **Calculate the MD5 Hash of the Exported File.** Once you have exported `file-mat.docx`, calculate its MD5 hash. Use a hashing tool like `Get-FileHash -Algorithm MD5 -Path "file-mat.docx"` (PowerShell), `md5sum file-mat.docx` (Linux/macOS), or online MD5 hash calculators. Record the calculated MD5 hash value.
    *   **Rationale:** Calculating the MD5 hash of the leaked file is critical for data integrity verification and future incident handling.

**Answer (File Name):** `file-mat.docx`

**Answer (MD5 Hash):**  *(The MD5 hash value of "file-mat.docx" would be inserted here after calculation and should be recorded in the investigation notes)*

**Relevance to Digital Forensics:**  Identifying the leaked file and its MD5 hash is crucial for:

*   **Data Breach Confirmation and Extent:**  Confirming precisely *what* data was stolen in the FTP data breach (the specific file `file-mat.docx`).
*   **Data Sensitivity and Value Assessment:**  Allowing for direct examination of the file content to determine the sensitivity and value of the compromised data. This informs risk assessment and prioritization of response efforts.
*   **Impact Assessment and Damage Control:**  Facilitating a thorough evaluation of the potential impact of the data breach, enabling appropriate damage control, notification procedures (if necessary), and remediation steps.
*   **Data Integrity and Chain of Custody:** The MD5 hash serves as a digital fingerprint of the leaked file, ensuring data integrity for future analysis, comparison, and potential legal proceedings. It helps maintain the chain of custody for this piece of digital evidence.

---

## Question 11: Determine Messaging Account Username from Network Traffic

**Question:** User "Ann" (IP address 192.168.1.158) sent a message over the wireless network to a suspicious computer that had recently connected. Analyze the `pcap1.pcap` file to determine the account username that Ann used to log in to the messaging system.

![image](https://github.com/user-attachments/assets/7d2897a9-831f-4111-b9a7-c6257074bc03)

**Steps:**

1.  **Open and Filter `pcap1.pcap` for Ann's Traffic.** Open the `pcap1.pcap` file in Wireshark. Apply a filter to isolate network traffic originating from Ann's computer, which has the IP address `192.168.1.158`. Use a Wireshark filter like `ip.src == 192.168.1.158`.
    *   **Rationale:** The question focuses on Ann's communication, so filtering for her traffic streamlines the analysis and focuses on relevant network activity.
2.  **Identify Messaging Protocol Traffic.** Examine the filtered traffic from Ann's computer. Look for network protocols that are commonly associated with messaging or chat applications. This might include protocols like HTTP/HTTPS (for web-based messaging), proprietary messaging protocols, or potentially older protocols like IRC or instant messaging protocols if applicable in the scenario. The image seems to suggest some form of messaging protocol, but *more protocol detail would be beneficial here to provide specific filtering guidance*.
    *   **Rationale:** Focusing on messaging protocol traffic is crucial to find evidence of messaging activity and potential login attempts related to the messaging system described in the question.
3.  **Search for Authentication or Login-Related Packets.** Within the identified messaging protocol traffic, look for packets that appear to be related to user authentication or login processes. This might involve looking for:
    *   Packets with keywords like "login", "auth", "username", "password", "credentials" in the packet content or headers.
    *   Packets exchanged with a server IP or hostname associated with the messaging service.
    *   Packets that follow a typical authentication handshake pattern.
    *   *Without more detail on the specific messaging protocol, it's difficult to provide precise filtering instructions here. Deeper protocol knowledge or further capture analysis would be required.*
    *   **Rationale:** Authentication packets are the most likely place to find usernames used for login. Identifying these packets is key to recovering the account name.
4.  **Extract Username from Authentication Packets.** Once you've located potential authentication packets, examine the packet details and attempt to extract the username. The method for extraction will depend heavily on the specific messaging protocol used and how it transmits usernames. *Without protocol specifics, it's impossible to give a precise extraction method.* The text simply states the answer is "user1", suggesting the username was found within the captured traffic, but the *exact steps* are not detailed in the provided materials.
    *   **Rationale:** Extracting the username answers the core question: identifying the messaging account username used by Ann.

**Answer:** `user1`

**Relevance to Digital Forensics:**  Analyzing messaging system activity and recovering usernames are important because:

*   **Communication Analysis:** Understanding who is communicating with whom, the nature of their communications, and the timing of messages can provide valuable context in an investigation.
*   **Insider Threat Detection:** Investigating suspicious communication patterns can help identify potential insider threats, unauthorized data sharing, or policy violations.
*   **Evidence of Coordination:** In some cases, message logs or network captures can provide evidence of coordination between attackers, accomplices, or individuals involved in illicit activities.

---

## Question 12: Determine MD5 Hash of File Sent via Messaging System

**Question:** What is the MD5 hash of the file that user "Ann" sent out via the messaging system?

![image](https://github.com/user-attachments/assets/f2fada8c-6436-42e3-b416-aa9346f9a8f4)

Here we can see that Ann was lured by a girl, took a file from the server and sent it out. That file is named `recipe.docx`.

*   *(Note: The MD5 hash value of `recipe.docx` would be here if calculated)*

![image](https://github.com/user-attachments/assets/59cd71e2-617b-47d8-85bd-12f06f671e6e)

**Steps:**

1.  **Analyze Network Capture for File Transfer Activity.** Re-examine the `pcap1.pcap` file (or the relevant network capture if it's different) for network traffic related to Ann sending a file via the messaging system. Look for traffic patterns or protocol indicators that suggest file transfer. The question mentions "file that Ann sent out" and `recipe.docx`. The image mentions `recipe.docx`. *Again, protocol specifics for the messaging system are needed for precise filtering guidance.*
    *   **Rationale:** File transfer activity within messaging traffic is the key to identifying the file being sent. Focusing on file transfer patterns in Ann's traffic will lead to the target file.
2.  **Identify the File Name (`recipe.docx`).** Locate the network traffic that indicates a file transfer and identify the file name being transferred. The text and image point to the file name `recipe.docx`. *The exact method for identifying the file name in the network capture is not detailed and would depend on the messaging protocol.*
    *   **Rationale:** Identifying the file name directly answers part of the question and tells us which file to focus on for hash calculation.
3.  **Export the File Content from the Network Capture.** If the file `recipe.docx` was transmitted in a way that allows for file extraction from the network capture (e.g., through HTTP file upload within the messaging system, or a file transfer protocol embedded in the messaging protocol), export the file's content from Wireshark. The export method will depend on the protocol.
    *   **Rationale:** Exporting the file from the network capture allows us to obtain a copy of the *actual* file that Ann sent for analysis, content review, and hash calculation.
4.  **Calculate the MD5 Hash of the Exported File (`recipe.docx`).** Once you have exported `recipe.docx`, calculate its MD5 hash using a hashing tool (PowerShell `Get-FileHash`, `md5sum`, online calculators). Record the MD5 hash value.
    *   **Rationale:** Calculating the MD5 hash of `recipe.docx` is crucial for data integrity verification and future analysis.  Similar to Question 10, the MD5 hash provides a digital fingerprint and allows for comparison with other copies of the file to ensure integrity and track potential modifications.

**Answer (MD5 Hash):** *(The MD5 hash value of `recipe.docx` would be inserted here after calculation and should be recorded in investigation notes)*

**Relevance to Digital Forensics:** Similar to Question 10, identifying the leaked file and its hash is crucial for:

*   **Data Breach Assessment:** Confirming the specific file (`recipe.docx`) sent via the messaging system represents a potential data leak or unauthorized data sharing incident.
*   **Content Analysis and Sensitivity Assessment:**  Enabling examination of the contents of `recipe.docx` to understand its nature, sensitivity, and potential impact of its unauthorized transmission.
*   **Impact Evaluation and Remediation:**  Facilitating assessment of the potential impact of this file being sent and informing appropriate remediation steps (e.g., policy review, user training regarding data handling).
*   **Data Integrity and Chain of Custody:** The MD5 hash provides a verifiable fingerprint of the file, essential for maintaining data integrity and chain of custody if the file becomes evidence in an investigation.

---

## Question 13: Determine System Timezone

**Question:** What is the system timezone configured on the compromised Linux server?

Using digital forensics software, view the `web-server-linux-003.ad1` file.

![image](https://github.com/user-attachments/assets/4084cb1a-46d9-453a-b617-362442a85a2e)

**Steps:**

1.  **Open Forensic Image in Digital Forensics Software.**  Use digital forensics software capable of analyzing disk images, especially `.ad1` format (like Autopsy, EnCase, FTK Imager, X-Ways Forensics). Open the provided image file `web-server-linux-003.ad1` within the chosen software.
    *   **Rationale:** Forensic software provides specialized tools for analyzing disk images, parsing file systems, and extracting system information, making it efficient for tasks like timezone identification.
2.  **Navigate to System Information or Operating System Details Section.** Most forensic software will automatically parse and present system information from a disk image. Look for a section within the software's interface that displays "System Information", "Operating System Details", "System Overview", or a similar category.
    *   **Rationale:** Forensic software often extracts key system configuration details and presents them in a readily accessible summary view, simplifying the process of finding information like timezone settings.
3.  **Locate Timezone Information.** Within the System Information or OS Details section, look for a field labeled "Time Zone", "Timezone", or similar. The image from Autopsy clearly shows "Time Zone: Europe/Brussels" in the "Operating System Information" section.
    *   **Rationale:** Forensic software is designed to parse and display key system settings, making finding the timezone information straightforward in the appropriate section of the tool.

**Answer:** `Europe/Brussels`

**Relevance to Digital Forensics:** Determining the system timezone is important for:

*   **Timestamp Correlation Accuracy:**  Ensuring accurate interpretation of timestamps from log files, file system metadata, and other digital artifacts. Timestamps are often recorded in local system time. Knowing the timezone allows for correct conversion to a standardized timezone (like UTC/GMT) for consistent analysis and correlation across different systems and data sources.
*   **Accurate Event Timeline Construction:** Building precise timelines of events is critical in investigations. Timezone information is essential for placing events in the correct chronological order and understanding the timing of activities relative to other systems and time zones.
*   **Geographic Context Clues:**  While not definitive, the timezone can sometimes provide clues about the geographic location of the system, user, or attacker, especially if correlated with other location-based data.

---

## Question 14: Determine Last User to Log In

**Question:** Based on the system logs, identify the username of the *last* user who successfully logged in to the compromised system.

![image](https://github.com/user-attachments/assets/8eaf755c-461b-4c42-8902-e538b1cac2d5)

Extract the `auth.log` file.

Put it into Kali Linux.

![image](https://github.com/user-attachments/assets/a9803a0e-3bbc-46a5-aa3a-8b6cffc0ab9d)

Put the "accepted password" (successful login) logs from the file into the `accepted_logins` file.

![image](https://github.com/user-attachments/assets/10def0ca-8770-47f5-a125-524fc4326a58)

Use the `sort` command to see the last log (last user) successfully logged in, which is root.

![image](https://github.com/user-attachments/assets/dade1fdd-37e8-4e3c-859f-e387e14b7c4b)

**Steps:**

1.  **Extract `auth.log` from Disk Image.** Use digital forensics software or command-line tools (if familiar with file system navigation within images) to extract the `auth.log` file from the `/var/log/` directory within the `web-server-linux-003.ad1` disk image.
    *   **Rationale:** `auth.log` is the primary log file on many Linux systems that records authentication-related events, including successful logins, failed logins, and user authentication attempts. It's the key source for identifying login activity.
2.  **Transfer `auth.log` to Analysis System (e.g., Kali Linux).** Transfer the extracted `auth.log` file to a system with suitable command-line tools for log analysis, such as a Kali Linux virtual machine. This facilitates efficient text processing and log filtering.
    *   **Rationale:** Kali Linux and other Linux distributions offer powerful command-line utilities (like `grep`, `sort`, `awk`, `sed`) that are highly effective for log analysis and text manipulation. Transferring the log file to such a system enables efficient analysis.
3.  **Filter `auth.log` for Successful Login Events.** Use `grep` (or a similar text filtering tool) to extract only the lines from `auth.log` that indicate successful logins. Filter for log entries containing keywords like "Accepted password" (common for SSH successful logins in `auth.log`). Save the filtered output to a new file, e.g., `accepted_logins`.  Command: `grep "Accepted password" auth.log > accepted_logins`
    *   **Rationale:** Filtering for successful login events isolates the specific log entries we need to answer the question, removing noise from other log data and making analysis more focused.
4.  **Sort Successful Login Logs in Reverse Chronological Order.** Use the `sort` command with the `-r` (reverse) option to sort the `accepted_logins` file chronologically in reverse order (newest to oldest).  Command: `sort -r accepted_logins`.
    *   **Rationale:** Sorting in reverse chronological order places the *most recent* successful login event at the *beginning* of the sorted output. This makes it easy to identify the last login.
5.  **Identify Last Logged-In User.** Examine the *first* line (because of reverse sorting) of the sorted `accepted_logins` file. This line will represent the most recent successful login event. Extract the username from this log line. The example shows the last login is related to the `root` user.
    *   **Rationale:** The first line of the reversed-sorted successful login logs directly answers the question: identifying the *last* user who successfully logged in to the system.

**Answer:** `root`

**Relevance to Digital Forensics:**  Identifying the last logged-in user is useful for:

*   **Recent User Activity Tracking:**  Understanding who was most recently active on the system. This can help establish a timeline of user actions and identify potential users of interest.
*   **Account Compromise Assessment:** If the last login is by an unexpected user, especially a privileged account like `root`, or occurs at an unusual time, it can indicate unauthorized access, account compromise, or malicious activity.  A `root` login, especially if unexpected, is often a red flag.
*   **Timeline Context and Event Sequencing:** The timestamp of the last login provides a recent point of reference in time for building a chronological timeline of events. It can help establish the sequence of actions and the recency of user interaction with the system.

---

## Question 15: Count Users with Login Shells

**Question:** How many user accounts on the system are configured with a valid login shell, indicating they are intended for interactive logins?

![image](https://github.com/user-attachments/assets/b8e00bf5-9f5a-4e92-b679-91e01a4bc963)

Extract the `passwd` file from `/etc`.

Continue to put it into Kali.

![image](https://github.com/user-attachments/assets/acab02a9-79c8-4b8d-91e1-898d4a660ced)

Use the `awk` command to count how many users in the `passwd` file just put in have a login shell:

![image](https://github.com/user-attachments/assets/bd9e216f-bcdc-4968-9d3e-4849725130d6)

**Steps:**

1.  **Extract `/etc/passwd` File from Disk Image.** Use forensic software or command-line tools to extract the `/etc/passwd` file from the `/etc/` directory within the `web-server-linux-003.ad1` disk image.
    *   **Rationale:** The `/etc/passwd` file is a critical system file on Linux systems that contains essential information about user accounts, including usernames, user IDs, group IDs, home directories, and login shells. It's the primary source for user account data.
2.  **Transfer `/etc/passwd` to Analysis System (e.g., Kali Linux).** Transfer the extracted `/etc/passwd` file to a system with command-line text processing tools, like Kali Linux.
    *   **Rationale:**  Kali Linux provides powerful tools like `awk` and `grep` that are well-suited for parsing structured text files like `/etc/passwd` and performing data extraction and counting operations.
3.  **Use `awk` to Count Users with Login Shells.** Employ the `awk` command to process the `/etc/passwd` file and count the number of user accounts that have a login shell configured. Use the `awk` command provided in the original document:

    ```bash
    awk -F':' '$7 != "/sbin/nologin" && $7 != "/bin/false" { count++ } END { print count }' passwd
    ```
    *   **Rationale:** The `awk` command efficiently parses the `/etc/passwd` file and applies specific criteria to count only user accounts that have a *valid login shell*.

        *   `-F':'`: Sets the field separator to a colon (`:`) to correctly parse the colon-separated fields in `/etc/passwd`.
        *   `'$7 != "/sbin/nologin" && $7 != "/bin/false"'`: This is the core filtering condition. It checks if the 7th field (`$7`, the login shell field in `/etc/passwd`) is *not* equal to `/sbin/nologin` *and* is *not* equal to `/bin/false`. User accounts with `/sbin/nologin` or `/bin/false` as their login shell are typically system accounts, service accounts, or accounts that are deliberately disabled for interactive logins. They are not intended for direct user logins.
        *   `{ count++ }`: If the condition is true (the user has a login shell other than `/sbin/nologin` or `/bin/false`), it increments a counter variable named `count`.
        *   `END { print count }`: After processing all lines in `/etc/passwd`, the `END` block executes, and it prints the final value of the `count` variable, which represents the total number of users with valid login shells.

**Answer:** `06` (meaning 6 user accounts have a login shell)

**Relevance to Digital Forensics:**  Counting users with login shells is relevant for:

*   **User Account Audit and Inventory:** Understanding the total number of interactive user accounts on the system. This provides a basic inventory of potentially active user accounts.
*   **Security Posture Assessment:** Reducing the number of users with login shells, especially for system accounts or service accounts that do not require interactive logins, is a security best practice. Limiting login shells reduces the attack surface and the potential for unauthorized interactive access.
*   **Account Management and Security Hardening:** Identifying accounts with login shells allows for review and management of user accounts. It helps ensure that only necessary accounts have interactive login capabilities, strengthening the system's overall security posture.

---

## Question 16: Analyze Logs Related to User Account Addition

**Question:** Extract log entries specifically related to user account addition activities and save these extracted log lines to a file named `b.txt` for further analysis.

![image](https://github.com/user-attachments/assets/e93232f9-5dff-4ef4-a50f-22570a075c14)
![image](https://github.com/user-attachments/assets/ac3859f2-c67b-4c9e-a81f-8186980f6d38)

User `vulnosadmin` created user `webmin`.

This is also displayed in the `bash_history` log of this user.

![image](https://github.com/user-attachments/assets/5660e146-46e3-4b69-a326-76f3dce8c8af)

**Steps:**

1.  **Identify Relevant Log Files for User Addition Events.** Determine which log file(s) on the Linux system are likely to record user account addition events. Common log files for user management actions include `auth.log`, `audit.log`, `syslog`, and potentially security-specific logs depending on the system's security configuration. In this case, the images show `auth.log` being examined.
    *   **Rationale:** Different Linux distributions and security configurations may log user management events in different log files. Knowing the relevant log files is crucial for targeted log analysis.
2.  **Filter Log File(s) for User Addition Keywords.** Use `grep` (or a similar text filtering tool) to filter the identified log file(s) for keywords and commands associated with user account creation. Common keywords include `useradd`, `adduser`, `create user`, `account created`, etc. The images show filtering `auth.log` for `"useradd"`.
    *   **Rationale:** Filtering for user addition keywords isolates the specific log entries that are relevant to user account creation activities, removing irrelevant log data and focusing the analysis on the target events.
3.  **Save Filtered Log Lines to `b.txt` File.** Redirect the output of the `grep` command (containing the filtered log lines) to a file named `b.txt`, as requested in the question. Command: `grep "useradd" auth.log > b.txt` (or similar, depending on the log file and keywords used).
    *   **Rationale:** Saving the filtered log lines to a separate file (`b.txt`) allows for:

        *   **Organized Data Storage:**  Keeping the user addition logs separate for focused analysis and reporting.
        *   **Easier Review and Sharing:**  Facilitating easier review of the user addition events and sharing the extracted log data with other investigators or stakeholders.
        *   **Further Analysis with Other Tools:** Enabling the use of other text analysis tools or scripts on the `b.txt` file if needed for deeper investigation.
4.  **Examine User `vulnosadmin`'s `bash_history` (Optional but Recommended).**  As a supplementary step (and as indicated in the provided text), examine the `.bash_history` file of the user `vulnosadmin` (typically located at `/home/vulnosadmin/.bash_history`). Check for commands related to user creation, particularly the `useradd` command. The images show that `vulnosadmin`'s `bash_history` contains the `useradd webmin` command.
    *   **Rationale:** Examining `bash_history` provides an *additional* source of evidence to corroborate the user creation events found in system logs and to attribute the action to a specific user (`vulnosadmin`). `bash_history` logs commands executed by users directly, offering a more direct record of user actions than system logs alone.

**Observation:** The analysis reveals that user `vulnosadmin` created the user account `webmin`. This user creation event is recorded in both `auth.log` (system log) and `vulnosadmin`'s `.bash_history` (user command history), providing converging evidence.

**Relevance to Digital Forensics:**  Analyzing user addition logs and command history is important to:

*   **Detect Unauthorized Account Creation:** Identify user accounts that were created without proper authorization or are potentially malicious.
*   **Attribute Actions to Specific Users:** Determine which user account was used to perform the user creation action, enabling attribution and accountability. In this case, it attributes the creation of `webmin` to `vulnosadmin`.
*   **Reconstruct Post-Compromise Activity:** User account creation is a common post-compromise action by attackers. Analyzing these logs helps reconstruct the attacker's activities after gaining initial access, such as establishing persistence or creating backdoors.

---

## Question 17: Count Users with Sudo Access

**Question:** Determine the number of user accounts on the system that are configured with `sudo` access, granting them elevated privileges.

Thus, the users who can use sudo here are: `root`, `php`, `mail`

**Steps:**

1.  **Extract and Examine `/etc/sudoers` and `/etc/sudoers.d/`.** Extract the `/etc/sudoers` file and the entire `/etc/sudoers.d/` directory from the `web-server-linux-003.ad1` disk image. These files control `sudo` permissions on Linux systems.
    *   **Rationale:** `/etc/sudoers` and `/etc/sudoers.d/` are the *definitive* configuration files that define sudo access rights on Linux systems. Analyzing these files is essential to determine which users or groups have sudo privileges.
2.  **Analyze `sudoers` Files for Sudo Rules.** Open and examine the contents of `/etc/sudoers` and each file within `/etc/sudoers.d/`. Look for lines that grant sudo privileges to users or groups. Common indicators of sudo access include lines starting with user or group names followed by rules like `ALL=(ALL:ALL) ALL` or more specific sudo rule sets.
    *   **Rationale:** Sudo rules in these configuration files explicitly define which users or groups are granted elevated privileges and under what conditions. Parsing these rules is necessary to identify sudo-enabled accounts.
3.  **Identify Users with Sudo Access.** Based on the analysis of the `sudoers` rules, identify the specific usernames that are explicitly granted `sudo` access. The provided text lists `root`, `php`, and `mail` as having sudo access. *The specific rules in `/etc/sudoers` that grant these users sudo access are not detailed in the provided materials and would require further examination of the actual `sudoers` files.*
    *   **Rationale:** Identifying the *usernames* with sudo access directly answers the question and provides a list of privileged accounts on the system.
4.  **Count Sudo Users.** Count the number of unique usernames identified as having `sudo` access. The answer provided is `3`.
    *   **Rationale:** Counting the number of sudo users provides a quantitative measure of the system's privileged account landscape. This number is important for security audits, risk assessments, and understanding the potential impact of account compromise.

**Answer:** `3`

**Relevance to Digital Forensics:** Knowing which users have `sudo` (superuser) access is critical for security assessment and incident response because:

*   **Privilege Management and Least Privilege Principle:** Sudo access grants users elevated privileges to execute commands as root, the most powerful user on a Linux system. Understanding sudo access helps assess if the principle of least privilege is being followed (granting only necessary privileges).
*   **Security Risk Assessment:** Users with `sudo` access pose a significantly higher security risk if their accounts are compromised because attackers can gain full root-level control of the system. Identifying sudo users highlights high-value target accounts.
*   **Impact Assessment of Account Compromise:** If a user with `sudo` access is compromised, the potential impact is much greater than if a standard user account is compromised. Knowing sudo users is crucial for understanding the potential damage from account breaches.
*   **Compliance and Auditing Requirements:** Many security compliance regulations require organizations to strictly control and audit sudo access. Identifying sudo users is a key step in meeting these compliance requirements and demonstrating proper access controls.

---

## Question 18: Identify File Deleted by the Root User

**Question:** Which specific file was deleted by the `root` user account on the system?

Go into root's history to see. Here there is an `rm` command, it removes file `37292.c`.

![image](https://github.com/user-attachments/assets/37ec87f2-2596-48c5-bfc9-d8fe6a979e9d)
![image](https://github.com/user-attachments/assets/4cd157d5-ca45-4435-8216-0333ab66964f)

**Steps:**

1.  **Extract Root User's `.bash_history` File.** Extract the `.bash_history` file from the `/root/` directory within the `web-server-linux-003.ad1` disk image. This file stores the command history for the `root` user's bash shell.
    *   **Rationale:** The `.bash_history` file for the `root` user is the primary source of information about commands executed by the `root` user on the system. It's the most direct place to look for commands initiated by `root`, including file deletion attempts.
2.  **Analyze `.bash_history` for `rm` Commands.** Open and examine the contents of the extracted `/root/.bash_history` file. Search for commands related to file deletion, specifically the `rm` command (remove). `rm` is the standard command in Linux and Unix-like systems for deleting files and directories.
    *   **Rationale:** The `rm` command is the direct indicator of file deletion actions. Filtering for `rm` commands within `root`'s command history will reveal files that `root` attempted to delete.
3.  **Identify the Deleted File Name.** Locate the specific `rm` command line within `.bash_history` that indicates a file deletion action. Extract the file name that is being targeted by the `rm` command. The images show the command line `rm 37292.c` within `root`'s history.
    *   **Rationale:** Extracting the file name from the `rm` command directly answers the question: identifying the specific file that was deleted by the `root` user.

**Answer:** `37292.c`

**Relevance to Digital Forensics:**  Tracking file deletion activity by `root` or any user is important for:

*   **Data Tampering Detection:**  Identifying if critical system files, logs, or user data files have been deleted, potentially to hide evidence of malicious activity or disrupt system operation. File deletion can be a sign of data tampering or attempts to cover tracks.
*   **Reconstructing User Actions and Intent:**  Understanding what files users were working with and potentially removing can provide context about user activities, system administration actions, or potential malicious intent if deletions are suspicious.
*   **Malware Analysis and Evasion Techniques:** Malware or attackers might delete files as part of their cleanup process to remove traces of their presence, evade detection by security tools, or disrupt forensic analysis. Tracking deleted files can reveal malware behavior and evasion tactics.

---

## Question 19: Identify the Content Management System (CMS) Installed

**Question:** What Content Management System (CMS) is installed and running on the web server?

![image](https://github.com/user-attachments/assets/186dce0d-5c76-4096-b10d-15c61e2de496)

**Steps:**

1.  **Access the Web Server via Web Browser.** Open a web browser and navigate to the IP address or hostname of the web server (`http://192.168.1.103/` as shown in the image).  Accessing the web server through a browser is a common first step in web application analysis.
    *   **Rationale:** Accessing the web server via a browser allows you to interact with the web application and potentially reveal information about the CMS or web technologies in use through the website's front-end interface.
2.  **Examine the Website's Default Page or Front Page Content.** Observe the content displayed on the website's default page (often the root directory `/`). Look for visual cues, text, or branding that might indicate a specific CMS. The image shows a default page with text clearly identifying "Drupal".
    *   **Rationale:** Many CMS platforms have distinctive default pages or branding elements that are visible on a fresh installation or when accessing the website's root directory. These visual cues can often quickly identify the CMS type.
3.  **Identify the CMS Based on Website Content.** Based on the visual cues and text on the website's page, identify the Content Management System (CMS) that is being used. In this case, the text "Drupal" clearly indicates that the CMS is Drupal.
    *   **Rationale:** Correctly identifying the CMS is crucial for targeted vulnerability assessment, security analysis, and understanding the web application's technology stack.

**Answer:** `Drupal`

**Relevance to Digital Forensics:**  Identifying the CMS installed on a web server is important for:

*   **Vulnerability Assessment and Security Auditing:** Knowing the specific CMS (like Drupal) and its version (see Question 20) allows for targeted research into known vulnerabilities and security weaknesses associated with that CMS. CMS platforms are frequently targeted by attackers, and specific versions often have documented vulnerabilities.
*   **Attack Surface Mapping and Threat Modeling:** CMS platforms have common attack vectors and known exploit techniques. Identifying the CMS helps map the potential attack surface and model potential threats specific to that CMS installation.
*   **Configuration Review and Security Misconfiguration Detection:** CMS installations often require specific configurations and security settings. Knowing the CMS type guides the review of its configuration for potential security misconfigurations, insecure settings, or deviations from security best practices.

---

## Question 20: Determine the CMS Version

**Question:** What is the specific version of the Content Management System (CMS) that is installed on the web server?

![image](https://github.com/user-attachments/assets/2bcccaff-f88f-49fd-876c-78f8f234a9ec)

**Steps:**

1.  **Examine Website Source Code (View Page Source).** In a web browser, view the source code of the website's front page (right-click on the page and select "View Page Source" or similar option). Search within the HTML source code for meta tags, comments, or specific code patterns that might reveal the CMS version. CMS platforms sometimes embed version information in the HTML source.
    *   **Rationale:** Website source code often contains metadata, comments, or code patterns that can reveal the CMS version or underlying technologies used to build the website.
2.  **Check for Version Files in the Web Directory (e.g., `CHANGELOG.txt`, `README.txt`).** If direct web browser access allows directory listing (which is a security misconfiguration in itself, but sometimes happens), or if you have access to the web server's file system (e.g., through the disk image), look for common version files within the CMS's document root directory. Files like `CHANGELOG.txt`, `README.txt`, `VERSION.txt`, or CMS-specific version files often contain version information.
    *   **Rationale:** Many software applications, including CMS platforms, include version files (like `CHANGELOG.txt` or `README.txt`) in their installation directories that explicitly state the software version.
3.  **Access CMS Admin Interface and Look for "About" or "Version" Information.**  Try to access the CMS administration interface (often located at paths like `/admin`, `/administrator`, `/wp-admin` for WordPress, `/drupal/admin` for Drupal, etc., though these paths vary depending on the CMS and configuration). Once in the admin interface (if you have credentials or if it's publicly accessible, which is a security issue), look for an "About", "Version", or "System Information" section within the admin dashboard. CMS admin interfaces often display version information in these sections.
    *   **Rationale:** CMS admin interfaces often provide system information and version details within their dashboards or "About" pages for administrative purposes.
4.  **Use CMS Detection Tools (e.g., `whatweb`, online CMS detectors).** Utilize automated CMS detection tools like `whatweb` (command-line tool) or online CMS version detectors. These tools analyze website headers, code patterns, and known CMS fingerprints to attempt to automatically identify the CMS type and version.
    *   **Rationale:** Automated CMS detection tools can quickly and efficiently scan a website and attempt to fingerprint the CMS and its version, saving manual analysis time.

**Answer:** *(The answer for the CMS version is missing from the original document. To answer this, further investigation of the Drupal installation using the steps above would be needed. The version would be determined through one of these methods and then recorded)*

**Relevance to Digital Forensics:** Knowing the *specific version* of the CMS is even more critical than just knowing the CMS type because:

*   **Version-Specific Vulnerability Identification:** Security vulnerabilities are often version-dependent. Knowing the *exact* CMS version allows for pinpointing known vulnerabilities that *specifically* affect that particular CMS installation. Vulnerability databases and security advisories are often indexed by software version.
*   **Targeted Exploit Research and Threat Assessment:** Attackers often target known vulnerabilities in specific CMS versions. Version information is essential for researching publicly available exploits, penetration testing tools, and understanding the immediate threats relevant to the identified CMS version.
*   **Patching and Remediation Prioritization:** Version information is crucial for applying the *correct* security patches and updates to address identified vulnerabilities. Patching is often version-specific. Knowing the version enables accurate patching and remediation efforts to secure the CMS installation.

---

## Question 21: Determine Port Listening for Attack Commands

**Question:** On which network port is the compromised system listening to receive attack commands from the hacker (e.g., for command and control communication)?

![image](https://github.com/user-attachments/assets/982a13d2-f376-4dfb-8e98-5991b0175482)

**Steps:**

1.  **Use Network Monitoring Tools (e.g., `netstat`, `ss`, `lsof`).** Utilize network monitoring commands on the compromised system (if it's live and accessible) or analyze the output of these commands if captured previously. Common Linux commands include:

    ```bash
    netstat -tulnp
    ss -tulnp
    lsof -i -n -P | grep LISTEN
    ```
    *   **Rationale:** These commands are standard Linux utilities for displaying network connection information, including listening ports, which are crucial for identifying services actively waiting for network connections.
2.  **Analyze Output for Listening Ports and Processes.** Examine the output of the network monitoring command. Look for lines that indicate ports in the "LISTEN" state.  Identify the port number and the process ID (PID) and program name associated with each listening port. Pay particular attention to ports that are:
    *   Unusual or unexpected for a web server (e.g., ports outside of standard web server ports like 80, 443, 8080).
    *   Associated with processes that seem suspicious or unknown.
    *   Listening on TCP (TCP is more commonly used for command and control).
    *   **Rationale:** Listening ports are the entry points through which network services and applications accept incoming network connections. Identifying listening ports helps pinpoint potential communication channels, including those used by attackers for command and control.
3.  **Correlate Listening Ports with Potential Malicious Activity.** Based on the identified listening ports, investigate further if any of them are:
    *   Known ports used by malware or command and control frameworks.
    *   Unexpected or undocumented for the system's intended function.
    *   Listening on ports that are not typically required for a web server.
    *   **Rationale:** Correlating listening ports with potential malicious activity helps distinguish legitimate services from potentially malicious backdoors or command and control channels. Unusual or unexpected listening ports are red flags that warrant deeper investigation.

**Answer:** *(The answer for the listening port is missing from the original document. To answer this, network analysis tools or examination of system configuration/process information would be needed to identify listening ports. The image provided is not directly relevant)*

**Relevance to Digital Forensics:**  Identifying listening ports, especially unusual or unexpected ports, is important for:

*   **Malware Detection and Command and Control Identification:** Malware often opens listening ports to establish command and control (C2) channels, allowing attackers to remotely control the compromised system and send commands. Identifying unusual listening ports can reveal potential C2 communication channels.
*   **Unauthorized Service Detection:** Unnecessary or unauthorized services listening on open ports increase the attack surface of the system and can represent security vulnerabilities. Identifying these ports helps detect potential security misconfigurations or unauthorized software installations.
*   **Network Security Assessment:** Understanding the services listening on open ports is crucial for a comprehensive network security assessment. It helps map the system's network services and identify potential vulnerabilities associated with exposed ports and services.

---

## Question 22: Determine PHP User's Root Directory (Home Directory)

**Question:** What is the path to the root directory (home directory) of the `php` user account on the system?

![image](https://github.com/user-attachments/assets/5f8c99d3-8106-4f90-aa21-20f9b00aa569)

**Steps:**

1.  **Examine `/etc/passwd` File for "php" User Entry.** If you haven't already extracted `/etc/passwd` (as in Question 15), extract it from the `web-server-linux-003.ad1` disk image. Open the `/etc/passwd` file and search for the line corresponding to the user account named "php".
    *   **Rationale:** The `/etc/passwd` file is the standard Linux system file that stores user account information, and it *includes* the home directory path for each user account. It's the most direct source for this information.
2.  **Extract Home Directory Path from `/etc/passwd` Entry.**  Once you locate the "php" user's entry in `/etc/passwd`, examine the 6th field of that line. In `/etc/passwd`, the 6th field is the "home directory" field. This field will contain the path to the home directory for the "php" user. The image seems to indicate the path is `/var/www`.
    *   **Rationale:** The 6th field in `/etc/passwd` is specifically designated to store the user's home directory path. Extracting this field directly provides the answer to the question.

**Answer:** `/var/www`

**Relevance to Digital Forensics:**  Knowing the home directory path of a user, especially a system user like "php" (often associated with web servers), is useful for:

*   **File System Navigation and Evidence Location:** Knowing the home directory path is essential for navigating the file system within the disk image and locating user-specific files, configuration data, user-created content, and potential evidence related to user activity.
*   **Security Auditing and Configuration Review:** Auditing the contents and permissions of user home directories, particularly for system users or service accounts, can help identify security misconfigurations, unauthorized file modifications, or suspicious files placed in user directories.
*   **Understanding Application Context and Data Storage:** For system users like "php" that are associated with web servers, the home directory might be related to the web server's document root directory, application files, or configuration files. Knowing the home directory provides context for understanding the user account's role and potential data storage locations.






## Question 23: What is the SHA256 hash value of the RAM Dump file?

**Question:** What is the SHA256 hash value of the RAM Dump file?

![image](https://github.com/user-attachments/assets/1e898190-7ec8-41b9-8d4a-1e424d006535)

**Steps:**

1.  **Use PowerShell to Calculate SHA256 Hash.**  Open PowerShell on a Windows system where the RAM dump file is accessible. Use the `Get-FileHash` cmdlet with the `-Algorithm SHA256` parameter to calculate the SHA256 hash of the RAM dump file. The command would be: `Get-FileHash -Algorithm SHA256 -Path "path\to\your\RAM_Dump_File.mem"`.  *(Replace `"path\to\your\RAM_Dump_File.mem"` with the actual path to your RAM dump file, e.g., `"E:\Dieu_tra_so\Lab4-Resource\Windows_RAM.mem"` or `"/root/Win10Home-20H2-64bit.mem"` as used in other questions)*.
    *   **Rationale:** Calculating the SHA256 hash provides a unique digital fingerprint of the RAM dump file.  **Why is this important?**
        *   **Data Integrity Verification:** The SHA256 hash is a more robust cryptographic hash compared to MD5.  It's crucial for verifying the integrity of the RAM dump file throughout the analysis process.  If the SHA256 hash is recalculated later and matches the original hash, it confirms that the file has not been altered or corrupted.
        *   **Chain of Custody:** Recording the SHA256 hash is essential for maintaining the chain of custody of the digital evidence.  It provides verifiable proof that the analyzed file is the original, unaltered RAM dump collected as evidence.
        *   **Uniqueness Identification:** The SHA256 hash uniquely identifies this specific RAM dump file.  It can be used to differentiate it from other memory captures and for record-keeping purposes.

**Answer (SHA256 Hash):** *(The SHA256 hash value will be displayed in the PowerShell output after running the command. This value should be recorded in investigation notes)*

**Relevance to Digital Forensics:**  Calculating the SHA256 hash of the RAM dump is a foundational step for ensuring data integrity and maintaining chain of custody, critical aspects of any digital forensics investigation.

---

## Question 24: When was the RAM Dump file collected according to the system time?

**Question:** When was the RAM Dump file collected according to the system time?

![image](https://github.com/user-attachments/assets/f73fdaca-2a95-4955-a527-b4d01d5e9d87)
![image](https://github.com/user-attachments/assets/7eae0a0a-cf88-4432-aa39-4283f70a4ac2)

**Steps:**

1.  **Use Volatility `windows.info` Plugin.** Execute the Volatility framework with the `windows.info` plugin to extract system information from the RAM dump file. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.info`.  *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:** The `windows.info` plugin in Volatility is specifically designed to extract general system information from a Windows memory dump, including the system time at the moment the memory dump was created.
2.  **Examine the "SystemTime" Section in Volatility Output.**  Carefully review the output of the `windows.info` plugin. Look for the section labeled "SystemTime". This section contains the system date and time as recorded in the memory dump.
    *   **Rationale:** The "SystemTime" field in the `windows.info` plugin output directly provides the timestamp of when the RAM dump was acquired, according to the captured system's clock. This is crucial for establishing a timeline and understanding the context of the memory capture.

**Answer (Collection Time):** *(The "SystemTime" value displayed in the Volatility output, as shown in the image, e.g., `2024-08-09 17:48:34 UTC+0000`)*

**Relevance to Digital Forensics:**  Knowing the RAM dump collection time is essential for:

*   **Timeline Creation and Event Correlation:** The collection timestamp provides a crucial anchor point for building a timeline of events. All information extracted from the RAM dump is relative to this point in time. It allows for correlating memory artifacts with other events from system logs or network captures that occur around the same time.
*   **Incident Contextualization:** The collection time provides context for the state of the system at a specific moment. It helps understand what processes were running, what network connections were active, and what data was present in memory *at that particular time*.
*   **Time Zone Awareness:** The `windows.info` plugin also often displays the timezone of the captured system.  This is critical for accurate interpretation of timestamps and for correlating events across systems in different timezones (as seen in Question 13).

---

## Question 25: Determine the PID of the "brave.exe" process

**Question:** Determine the PID of the "brave.exe" process in the RAM Dump file above.

![image](https://github.com/user-attachments/assets/3115a0ed-fb03-455f-8c4c-de60a4febea4)

**Steps:**

1.  **Use Volatility `windows.pslist` Plugin with `grep`.** Execute the Volatility framework with the `windows.pslist` plugin to list running processes from the RAM dump.  Use `grep` to filter the output and specifically search for processes named "brave.exe". The command is:  `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.pslist | grep brave.exe`. *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:** The `windows.pslist` plugin in Volatility is designed to list running processes from a Windows memory dump, similar to Task Manager or `pslist.exe`.  Using `grep brave.exe` efficiently filters this list, directly targeting the process we are interested in.
2.  **Examine `grep` Output for PID.** Review the output of the command. The `grep` command will display lines from `windows.pslist` output that contain "brave.exe". The PID (Process ID) is typically the first numerical value listed on each line in the `windows.pslist` output.  The example shows the PID as `4856`.
    *   **Rationale:** The `windows.pslist` plugin provides process information in a structured format. The PID is a key identifier for each process, allowing for targeted analysis of specific processes in subsequent steps.

**Answer (PID of brave.exe):** `4856`

**Relevance to Digital Forensics:** Identifying the PID of a specific process like "brave.exe" is important because:

*   **Process Identification and Tracking:** The PID uniquely identifies a specific instance of the `brave.exe` process that was running at the time of the memory dump. This allows you to track and analyze this particular process throughout the RAM dump analysis.
*   **Targeted Process Analysis:** Knowing the PID enables you to use other Volatility plugins to perform more targeted analysis on this specific process, such as:
    *   Dumping its memory (`memdump` plugin).
    *   Examining its command line (`cmdline` plugin).
    *   Listing its open files (`handles` or `filescan` plugins).
    *   Analyzing its network connections (`netscan` plugin - as seen in the next question).
*   **Behavioral Analysis:** Analyzing a specific process like a browser (brave.exe) can reveal user browsing history, web activity, potentially accessed websites, and other browser-related artifacts present in memory.

---

## Question 26: How many network connections were established at the time the RAM Dump file was collected?

**Question:** How many network connections were established at the time the RAM Dump file was collected? (enter only the number)

![image](https://github.com/user-attachments/assets/8d32bac1-b8b1-42c4-8019-8fe29a1efebf)
![image](https://github.com/user-attachments/assets/31f7e4c9-012e-49c0-b215-df923f5dfdb7)
![image](https://github.com/user-attachments/assets/4b6a8297-2e57-46a8-9d55-8ef8ce42395c)

**Steps:**

1.  **Use Volatility `netscan` Plugin.** Execute the Volatility framework with the `netscan` plugin to scan for and list network connection objects found in the RAM dump. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem netscan`. *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:** The `netscan` plugin in Volatility is specifically designed to scan memory and identify network-related objects, including information about active and recently closed network connections.
2.  **Examine `netscan` Output for "Established" Connections.** Review the output of the `netscan` plugin. Look for entries where the "State" column indicates "Established". These entries represent network connections that were actively established at the time the RAM dump was captured.
    *   **Rationale:** "Established" connections are those that were actively open and communicating at the moment the memory dump was taken. These are often of high forensic interest as they represent active network communication at the time of capture.
3.  **Count the Number of "Established" Connections.** Count the number of lines in the `netscan` output that have the "State" as "Established". The example shows a total of `08` established connections.
    *   **Rationale:** Counting the established connections provides a quantifiable measure of the network activity at the time of the memory capture. This number can be used for reporting and for comparing network activity across different time points or systems.

**Answer (Number of Established Connections):** `08`

**Relevance to Digital Forensics:**  Determining the number of established network connections at the time of the RAM dump is important because:

*   **Network Activity Assessment:** It provides a snapshot of the network communication activity at the moment of capture. A high number of established connections, or connections to unusual or suspicious IPs, can indicate network-intensive applications running, potential data exfiltration, or command and control communication.
*   **Malware Detection (Network Indicators):** Malware often establishes network connections for communication with command-and-control servers or for spreading to other systems. Identifying and analyzing established connections can reveal network-based indicators of compromise (IOCs).
*   **Process-to-Network Mapping (with further analysis):** While `netscan` provides connection information, you can correlate this with process information (e.g., using `windows.netstat` or further `netscan` analysis with process filtering - see next question) to determine which processes were responsible for establishing those connections. This process-to-network mapping is crucial for understanding application behavior and identifying potentially malicious processes engaging in network communication.

---

## Question 27: Chrome has an established network connection with which FQDN domain name?

**Question:** Chrome has an established network connection with which FQDN domain name?

![image](https://github.com/user-attachments/assets/788cf100-3ea1-4c5c-85c7-e26266961763)
![image](https://github.com/user-attachments/assets/2957b98b-3438-4f1a-9b14-cda93535a07d)
![image](https://github.com/user-attachments/assets/44f138e1-59b2-4e31-a0a8-f1cf095f2cc1)

**Steps:**

1.  **Use Volatility `netscan` Plugin with `grep chrome.exe`.** Execute the Volatility framework again with the `netscan` plugin, but this time, add `grep chrome.exe` to filter the output and specifically focus on network connections associated with the "chrome.exe" process. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem netscan | grep chrome.exe`. *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:** Filtering `netscan` output by `grep chrome.exe` isolates the network connections established by the Chrome browser process. This allows us to focus specifically on Chrome's network activity at the time of the memory capture.
2.  **Identify Established Connection for Chrome and Foreign IP.** Examine the filtered `netscan` output. Look for a line where the "Process" column shows "chrome.exe" and the "State" column is "Established".  Identify the "ForeignIP" address associated with this established Chrome connection.  The example shows one established connection for chrome.exe, and you need to retrieve its ForeignIP.
    *   **Rationale:** Focusing on "Established" connections for "chrome.exe" pinpoints the active network connection initiated by Chrome at the time of the memory capture. The "ForeignIP" is the remote IP address Chrome was connected to.
3.  **Use `nslookup` to Resolve Foreign IP to FQDN.**  Take the "ForeignIP" address identified in the previous step. Use the `nslookup` command (or an online DNS lookup tool) to perform a DNS reverse lookup and resolve the IP address to a Fully Qualified Domain Name (FQDN). The command is: `nslookup <ForeignIP>`.  *(Replace `<ForeignIP>` with the actual IP address from the `netscan` output)*. The example uses `nslookup` and resolves the IP to `...protonmail.ch`.
    *   **Rationale:** While IP addresses are useful, domain names (FQDNs) are often more informative and human-readable. Resolving the IP to a domain name can provide context about the remote server Chrome was connected to.  Domain names can reveal the service or organization Chrome was communicating with (e.g., `protonmail.ch` indicates communication with ProtonMail).

**Answer (FQDN Domain Name):** `protonmail.ch`

**Relevance to Digital Forensics:** Determining the FQDN domain name associated with Chrome's established network connection is important because:

*   **Browsing Activity Context:** It provides context about Chrome's network activity.  Knowing the domain name reveals *what* website or service the user was likely interacting with using Chrome at the time of the memory capture.  In this case, `protonmail.ch` suggests the user was accessing the ProtonMail secure email service.
*   **Potential Evidence of User Actions:**  Browsing history, webmail access, or other online activities performed within Chrome and directed towards specific domain names can be relevant evidence in an investigation, depending on the nature of the case.
*   **Identifying Communication Partners:**  Domain names can help identify the remote entities or organizations the user was communicating with or accessing through Chrome. This can be crucial for understanding communication patterns and potential relationships in an investigation.

---

## Question 28: What is the MD5 hash value of the executable file with PID 6988?

**Question:** What is the MD5 hash value of the executable file with PID 6988?

![image](https://github.com/user-attachments/assets/8f6af695-3f6c-406e-ae6c-89402120a3b6)
![image](https://github.com/user-attachments/assets/0020f8a2-e5b2-43a0-9140-c4f6cbcad602)

**Steps:**

1.  **Use Volatility `windows.cmdline` Plugin to Identify Executable Name.** Execute the Volatility framework with the `windows.cmdline` plugin and specify the PID `6988` to retrieve the command line used to start the process with that PID. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.cmdline --pid 6988`. *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:** The `windows.cmdline` plugin in Volatility retrieves the command line string used to launch a process.  This command line typically includes the full path and name of the executable file that started the process. This step is necessary to determine *which* executable file is associated with PID 6988 before we can calculate its hash.
2.  **Examine `windows.cmdline` Output to Get Executable Name.** Review the output of the `windows.cmdline` command. The output will show the command line string for PID 6988. In the example, the command line reveals that the executable is `"C:\Users\user1\AppData\Local\Microsoft\OneDrive\OneDrive.exe"`. From this, we can extract the executable name as `OneDrive.exe`.
    *   **Rationale:**  The command line output provides the full path to the executable file.  Extracting the executable name (e.g., `OneDrive.exe`) allows us to then calculate the hash of *that specific executable file*.
3.  **Calculate MD5 Hash of `OneDrive.exe` (on a Clean System).**  Since we know the executable name is `OneDrive.exe`, and assuming it's a legitimate Windows file, you can calculate the MD5 hash of a *known clean copy* of `OneDrive.exe`.  **Important:** Do *not* calculate the hash directly from the RAM dump. Calculate it from a known good file on a clean Windows system to get a baseline hash for comparison.  Use PowerShell or a similar tool to calculate the MD5 hash. The example shows using PowerShell: `Get-FileHash -Algorithm MD5 -Path "C:\Path\to\Clean\OneDrive.exe"`. *(Replace `"C:\Path\to\Clean\OneDrive.exe"` with the actual path to a clean copy of `OneDrive.exe`)*.
    *   **Rationale:** Calculating the MD5 hash of a *known clean copy* of `OneDrive.exe` provides a baseline or reference hash value for comparison.  This baseline hash can then be compared to the hash of `OneDrive.exe` potentially extracted from the RAM dump (although this task doesn't explicitly ask for extraction from the RAM dump, it's a common next step in malware analysis).  Comparing the hashes can help determine if the `OneDrive.exe` process in the RAM dump is legitimate or potentially modified or malicious (if its hash differs from the known good hash).

**Answer (MD5 Hash of OneDrive.exe):** *(The MD5 hash value of `OneDrive.exe` calculated from a clean system will be displayed in the PowerShell output. This value should be recorded in investigation notes)*

**Relevance to Digital Forensics:**  Determining the MD5 hash of an executable file associated with a PID from a RAM dump is important for:

*   **Executable Identification and Verification:**  By getting the executable name and calculating its hash, you can identify the specific program that was running with PID 6988. Comparing the hash to known good hashes (from a clean system or malware databases) can help verify if the executable is legitimate or potentially malicious.
*   **Malware Analysis and Threat Intelligence:** If the MD5 hash of `OneDrive.exe` (or any executable) differs from the known good hash, it could indicate that the file has been modified, potentially by malware or an attacker.  This hash can then be used to:
    *   Search malware databases (like VirusTotal) to see if the hash is associated with known malware.
    *   Further analyze the executable file (if extracted from memory or disk) for malicious functionality.
*   **Process Legitimacy Assessment:**  Hashing executables helps assess the legitimacy of processes running in memory.  Unexpected or modified system executables are often indicators of compromise.

---

## Question 29: What is the content starting at offset 0x45BE876 with a length of 6 bytes?

**Question:** What is the content starting at offset 0x45BE876 with a length of 6 bytes?

![image](https://github.com/user-attachments/assets/a096ba0b-999d-4f84-baa3-77129a132a0e)

**Steps:**

1.  **Open RAM Dump File in a Hex Editor.** Use a hex editor software (like Hex Workshop, HxD, or others) to open the RAM dump file (`Win10Home-20H2-64bit.mem` or `Windows_RAM.mem`).
    *   **Rationale:** Hex editors allow you to view and examine the raw binary data of a file at the byte level. This is essential for inspecting specific memory locations defined by offsets.
2.  **Navigate to the Specified Offset.** In the hex editor, use the "Go To Offset" or similar function to navigate to the memory address `0x45BE876`. Enter this hexadecimal offset value into the hex editor's navigation tool.
    *   **Rationale:** Offsets are used to pinpoint specific locations within a file or memory region. Navigating to the specified offset allows you to examine the data starting at that exact memory address.
3.  **Select and Examine 6 Bytes of Data Starting at the Offset.**  Once you are at offset `0x45BE876` in the hex editor, select the next 6 bytes of data *starting from* that offset.  The hex editor will display the hexadecimal representation of these 6 bytes. The example shows the 6 bytes as `68 61 61 ...` and the ASCII interpretation starting with "haa...".
    *   **Rationale:** The question specifies a length of 6 bytes. Selecting and examining these bytes allows you to read the raw data at that memory location and interpret it as ASCII or other encodings, as needed.
4.  **Interpret the Hex Data (Optional).**  Optionally, interpret the hexadecimal bytes as ASCII text to see if they represent human-readable characters. The example shows that the 6 bytes, when interpreted as ASCII, start with the word "hacker".
    *   **Rationale:** Interpreting hex data as ASCII or other character encodings can reveal meaningful strings or text embedded within the raw binary data. In this case, finding "hacker" could be a relevant keyword or indicator within the memory dump.

**Answer (Content at Offset 0x45BE876):** `68 61 61 ...` (Hexadecimal representation of the 6 bytes) and starting with the word "hacker" (ASCII interpretation)

**Relevance to Digital Forensics:**  Examining specific offsets and byte sequences in a RAM dump using a hex editor is important for:

*   **Keyword Searching and String Extraction (Manual):** While automated string extraction tools exist (like the `strings` command), manually examining offsets in a hex editor can be useful for:
    *   Verifying automated string extraction results.
    *   Finding strings or data patterns that might not be easily found by automated tools.
    *   Examining data in context, surrounding bytes, and memory structures.
*   **Malware Signature and Pattern Analysis:** Malware often has specific byte patterns or strings embedded within its code or data sections. Hex editor analysis can help locate these patterns, which can be used to:
    *   Identify malware signatures manually.
    *   Understand malware behavior and functionality by examining its data structures.
*   **Data Carving and Recovery (Manual):** In some cases, hex editor analysis can be used to manually carve or recover data fragments from memory or disk images, especially if automated carving tools fail or for very specific data recovery tasks.

---

## Question 30: What is the creation date and time of the parent process of "powershell.exe"?

**Question:** What is the creation date and time of the parent process of "powershell.exe"?

![image](https://github.com/user-attachments/assets/ecd409b6-e5fa-455b-bbab-52160aca2f00)
![image](https://github.com/user-attachments/assets/b9bf75a1-a52d-41ea-996d-8ec868d98b81)
![image](https://github.com/user-attachments/assets/721efccc-13c7-4eb8-a44e-480040551124)

**Steps:**

1.  **Use Volatility `windows.pstree` Plugin with `grep powershell.exe` to Find Parent PID (PPID).** Execute the Volatility framework with the `windows.pstree` plugin to display a process tree of running processes from the RAM dump. Use `grep powershell.exe` to filter the output and specifically find the "powershell.exe" process and its parent process. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.pstree | grep powershell.exe`. *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:** The `windows.pstree` plugin in Volatility visualizes the parent-child relationships between processes, making it easy to identify the parent process (PPID) of a given process (like `powershell.exe`).
2.  **Examine `windows.pstree` Output for PPID.** Review the output of the command. The `grep` output will show the line for "powershell.exe" and its parent process.  Note the PPID (Parent Process ID) listed for "powershell.exe".  The example shows the PPID as `4352`.
    *   **Rationale:** The `windows.pstree` output provides the PPID, which is the Process ID of the parent process that launched `powershell.exe`.  Knowing the PPID is crucial for finding information about the parent process itself.
3.  **Use Volatility `windows.cmdline` Plugin with Parent PID to Identify Parent Process Name.** Execute Volatility again with the `windows.cmdline` plugin, but this time, use the PPID `4352` (identified in the previous step) to find the command line and executable name of the parent process. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.cmdline --pid 4352`.
    *   **Rationale:**  Using the `windows.cmdline` plugin with the PPID allows us to determine *which* process is the parent of "powershell.exe". The command line output will reveal the executable name of the parent process. The example shows the parent process is `explorer.exe`.
4.  **Use Volatility `windows.pslist` Plugin with Parent PID to Get Creation Time.** Execute Volatility one more time with the `windows.pslist` plugin and use `grep 4352` to filter for information about the process with PID `4352` (the parent process, `explorer.exe`). The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.pslist | grep 4352`.
    *   **Rationale:** The `windows.pslist` plugin provides process listing information, including the "Create Time" of each process.  By filtering for the parent process's PID (`4352`), we can retrieve the creation date and time of the parent process (`explorer.exe`).
5.  **Examine `windows.pslist` Output for Creation Time of Parent Process.** Review the output of the `windows.pslist` command. Look for the "Create Time" column for the process with PID `4352` (`explorer.exe`). This timestamp represents the creation date and time of the parent process.
    *   **Rationale:** The "Create Time" from `windows.pslist` for the parent process directly answers the question: what is the creation date and time of the parent process of "powershell.exe"?

**Answer (Creation Date and Time of Parent Process):** *(The "Create Time" value for `explorer.exe` with PID 4352, as displayed in the Volatility `windows.pslist` output, e.g., `2024-08-09 17:48:29 UTC+0000`)*

**Relevance to Digital Forensics:**  Determining the parent process and its creation time for "powershell.exe" is important because:

*   **Process Provenance and Context:** Understanding the parent-child process relationship helps establish the provenance and context of "powershell.exe". Knowing that "explorer.exe" (the Windows Explorer shell) is the parent process is generally normal and expected. However, if the parent process were something unusual or suspicious, it could indicate malicious process injection or an unusual process execution chain.
*   **Timeline Reconstruction and Event Sequencing:** The creation time of the parent process (`explorer.exe`) and its relationship to "powershell.exe" helps build a more detailed timeline of process execution events. It allows you to sequence events and understand the order in which processes were started.
*   **Detecting Process Injection or Anomalous Process Trees:** In cases of malware or malicious activity, "powershell.exe" might be launched by a suspicious or unexpected parent process, not `explorer.exe`. Analyzing process trees and parent-child relationships can help detect process injection, malicious process spawning, and other anomalous process execution patterns.

---

## Question 31: What is the full path and name of the last file opened in notepad?

**Question:** What is the full path and name of the last file opened in notepad?

![image](https://github.com/user-attachments/assets/f6fdc8a8-db18-4ef3-a027-66d867fca6d8)
![image](https://github.com/user-attachments/assets/ed619ec1-f351-44c5-9a9e-7ea08115ae52)

**Steps:**

1.  **Use Volatility `windows.pslist` Plugin with `grep notepad.exe` to Find Notepad PID.** Execute the Volatility framework with the `windows.pslist` plugin and use `grep notepad.exe` to filter for information about the "notepad.exe" process. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.pslist | grep notepad.exe`. *(Adjust the path to the RAM dump file if necessary)*.
    *   **Rationale:**  Similar to Question 25, using `windows.pslist` and filtering for "notepad.exe" helps identify the PID of the notepad process, which is needed for the next step.
2.  **Examine `windows.pslist` Output for Notepad PID.** Review the output and note the PID for "notepad.exe". The example shows the PID as `2520`.
    *   **Rationale:**  Knowing the PID of notepad allows us to target further Volatility plugins to retrieve information *specific* to this notepad process instance.
3.  **Use Volatility `windows.cmdline` Plugin with Notepad PID to Get Command Line.** Execute Volatility again with the `windows.cmdline` plugin and use the notepad PID `2520` to retrieve the command line used to start notepad. The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.cmdline --pid 2520`.
    *   **Rationale:** The `windows.cmdline` plugin, when used with a specific PID, retrieves the command line string used to launch that process. For notepad, the command line *sometimes* (but not always, depending on how notepad is launched and what arguments are passed) includes the path to the file that was opened when notepad started.
4.  **Examine `windows.cmdline` Output for File Path.** Review the `windows.cmdline` output for PID `2520`. Look at the command line string. If notepad was launched by opening a file, the full path and name of the opened file might be present in the command line arguments. In the example, the command line shows: `"C:\WINDOWS\system32\notepad.exe C:\Users\user1\Documents\Lab_4_strings_keywords.txt"`. This indicates that "C:\Users\user1\Documents\Lab_4_strings_keywords.txt" was opened in notepad.
    *   **Rationale:** Analyzing the command line of notepad is a *potential* way to find the last opened file, *if* the file path is passed as a command-line argument when notepad is launched. Note that this method is not always reliable as the file path might not always be included in the command line. More robust methods for finding recently opened files would involve analyzing registry keys, jump lists, or file system metadata.

**Answer (Full Path and Name of Last Opened File in Notepad):** `C:\Users\user1\Documents\Lab_4_strings_keywords.txt`

**Relevance to Digital Forensics:**  Determining the last file opened in notepad (or other text editors) can be useful for:

*   **User Activity Tracking:**  It provides insight into what documents or files the user was recently viewing or working with using notepad. This can be relevant for understanding user actions and potential files of interest in an investigation.
*   **Document Context and Content Discovery:**  Knowing the name and path of the last opened file can lead to the discovery of potentially relevant documents or text files on the system.  The file name itself (`Lab_4_strings_keywords.txt` in this example) might even be suggestive of its content or purpose.
*   **Limited Evidence - Command Line Dependency:** It's important to remember that relying solely on the command line to find the last opened file in notepad is limited. It depends on whether the file path was included in the command line when notepad was launched. Other methods, like registry analysis, are generally more reliable for tracking recently opened files.

---

## Question 32: How long did the suspect use the Brave browser?

**Question:** How long did the suspect use the Brave browser?

![image](https://github.com/user-attachments/assets/59475ec1-6ad8-4294-8a2b-21e2b31449e6)

**Steps:**

1.  **Use Volatility `windows.pslist` Plugin with `grep brave.exe` to Get Create Time and Exit Time.** Execute the Volatility framework with the `windows.pslist` plugin and filter for "brave.exe" using `grep` (as in Question 25). The command is: `python3 vol.py -f /root/Win10Home-20H2-64bit.mem windows.pslist | grep brave.exe`.
    *   **Rationale:** The `windows.pslist` plugin provides process listing information, including the "Create Time" (when the process started) and "Exit Time" (when the process terminated, if it had exited at the time of memory capture).
2.  **Examine `windows.pslist` Output for Create Time and Exit Time.** Review the output of the command and note the "Create Time" and "Exit Time" values for the "brave.exe" process. The example shows a Create Time and an Exit Time.
    *   **Rationale:** These timestamps from `windows.pslist` provide the start and end times of the Brave browser process's execution, as recorded in the memory dump.
3.  **Calculate the Time Difference.** Subtract the "Create Time" from the "Exit Time" to calculate the duration for which the Brave browser was running. Perform the time subtraction manually or using a time calculation tool. The example shows the calculation: `17:50:56 - 17:48:45 = 00:02:11`.
    *   **Rationale:** Subtracting the start time from the end time gives the elapsed time, which represents the duration for which the Brave browser process was active. This duration can provide insights into user browsing session length.

**Answer (Duration of Brave Browser Usage):** `02:11` (2 minutes 11 seconds)

**Relevance to Digital Forensics:**  Determining the duration of browser usage (like Brave browser in this case) can be useful for:

*   **User Activity Timeline and Session Analysis:**  Knowing how long a browser was active can contribute to building a timeline of user activity. Browser usage duration can indicate how long a user was engaged in web browsing or online activities.
*   **Contextualizing Browser History and Web Activity:**  Combining browser usage duration with browser history analysis (if browser history artifacts are recovered from memory or disk) can provide a more complete picture of the user's web browsing session, including the timing and duration of website visits.
*   **Incident Reconstruction and Activity Mapping:** In incident response scenarios, browser usage duration can help reconstruct the attacker's or user's actions leading up to or during an incident, particularly if web browsing activity is relevant to the investigation.











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
