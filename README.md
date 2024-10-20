# Wireshark FTP

**Overview:** Analyzed FTP traffic to identify and extract sensitive information, demonstrating the risks of unencrypted FTP connections.

**Skills Developed:** FTP packet inspection, extracting passwords, using network analysis tools, decrypting captured packets.

**Tools Used:** Wireshark, Kali Linux, fcrackzip, CyberChef, hashcat.


---

**Lab Details**

Introduction

File Transfer Protocol (FTP) is a standard network protocol used for transferring files between a client and a server on a computer network. This operates on the application layer of the Open Systems Interconnection (OSI) model, a conceptual model created by the International Organization for Standardization which enables diverse communication systems to communicate using standard protocols (Cloudflare, n.d.). FTP uses a client-server architecture to facilitate the transfer of data and typically runs on port 21. FTP can operate in either active or passive mode for data transmission. The protocol involves a series of commands and responses between the client and the server, allowing for the uploading, downloading, renaming, deleting, or manipulation of files. While FTP is widely used due to its simplicity and effectiveness, it is extremely insecure as it transmits data, including usernames and passwords in plaintext. This lack of encryption makes it vulnerable to interception and eavesdropping using tools such as Wireshark and tcpdump for analyzing and securing FTP traffic. Wireshark is a popular network sniffing tool that provides a Graphical User Interface (GUI) to decode many protocols and filters monitoring a network interface. Tcpdump is also a common used network analysis tool that provides simplicity and efficiency in one interface. It is a free, open source network utility tool that analyzes packets, tracks, and records TCP/IP traffick between a network and the machine it is run on (Educba, n.d.). These tools help in capturing and inspecting network data, identifying potential vulnerabilities, and ensuring sensitive information is not exposed.

Objective

The objective of this lab is to analyze FTP traffic and identify sensitive information transmitted over a network, such as usernames and passwords within transferred files. This involves using Wireshark to filter and inspect network captures, extracting relevant data, and understanding the implications of transmitting sensitive information over unencrypted channels. To achieve this,a modern operating system like Windows, Linux, or macOS, and software tools including Wireshark, Linux command line tools (specifically the file command), and a password cracking tool like ‘fcrackzip’ are essential. This lab will be conducted in a VirtualBox environment using a Kali Virtual environment on a host operating system using Windows 11 using Wireshark for a packet capture analysis. 

Results and Analysis

Upon opening the packet capture from Wireshark, there are many different protocols from Transmission Control Protocol (TCP), Internet Control Message Protocol (ICMP), and FTP. However, to focus only on FTP the user must filter for only FTP I the top where it shows display filer. The individual can type ‘ftp’ in lower case and then hit enter. This will display only the FTP protocols in the pack capture. Once Wireshark is filtering for only FTP protocols, the user can identify packets and information that display sensitive information. For example, one request shows ‘confidential_file’ and another response packet shows ‘PASS’ and ‘USER’. This can most likely display a username and password. The screenshot below shows both packet information. 

![image](https://github.com/user-attachments/assets/475bef65-292b-45aa-b7de-bb2dfe7974d5)

 
However, if the passwords are not out in the open and there is need for further investigation. The user will right click on the packet that is suspicious or the user wishes to look into. In this example, the user would look into the ‘confidential file’. The user will right click on the packet then click the follow tab, then click ‘tcp stream’. This will give the user more information about the specific packet. The following screenshot is the results from the confidential file packet.

 ![image](https://github.com/user-attachments/assets/10302c5a-5ff2-4d4a-ba49-0a7a4e195f9f)


The following information displays the username as ‘supafly’ and the password as ‘sup4secure’. The packets that these are displayed in Wireshark are in packets 16 and 27. When extracting the packets between 93 and 99 using ‘tcp.stream’ the following screenshot below appears. 


 ![image](https://github.com/user-attachments/assets/243a2bfc-7249-45e5-94b8-2424fee57867)


In Kali Linux the command ‘file’ will determine what type of file is within a directory and displays a description of the type. The ‘file’ command can help identifying formats for files especially if they are missing or misleading. For example, the user will execute file ‘exfiltrated.pcap’ in the linux terminal about the given packet capture file. Unlike Windows, the file command is for Unix-based operating systems. If a user wanted to determine the file type in Windows, there would have to be either many clicks with a mouse or by running the type command in PowerShell, however, it would be possible. The screenshot below shows the command and output for ‘file’ of the given packet analysis file. 
 
![image](https://github.com/user-attachments/assets/48cef729-0f77-4454-8b16-4eb29efc45a0)


To crack the password within Wireshark the user will use the tool, fcrackzip. This tool is used primarily for cracking password passed zip files. However, in this case the tool will be used to find a password within a packet in Wireshark. First, the packet number 94 containing the username and password previously must be saved to a file in a directory that is easily accessible. This can be saved by right clicking on the packet and then clicking on follow then clicking on tcp stream. Once the window appears click ‘save as..’ and choose the name and directory of the users choice. Then the user will run the command sudo fcrackzip -b -c aA1 -l 1-9 ‘ftp_transfer.pcap(2).zip’ once the user is in the directory that contains the corresponding zip file to crack. To explain this command, fcrackzip will run -b for bruteforce, -c for charset, this sets specifications within characters for bruteforce passwords in this command it will be lowercase, uppercase and numbers since there is a lowercase a, uppercase a, and a number 1. The flag -l specifies the length of the password and in this command, it will search for passwords in length 1-9 characters in length in the zip file. After the command has run, it will ask for the root password, and then find an id number containing numbers and letters. The user will then run the command unzip -P (letters and numbers) ‘ftp_transfer.pcap(2).zip’ The following screenshot shows both commands and their outputs. 
 

![image](https://github.com/user-attachments/assets/ef4a32d1-654c-4c1a-8b03-505fc5d9ec9d)


Once this is finished, the user will then run the command base64 (file saved from wireshark) > (txt file of choice). For example, base64 extracted > decoded.txt. This will created the packet capture into a base64 hash then place the hash into a text file called decoded. Once the user runs the cat decoded.txt it will display the information in a base64 hash. The screenshot below shows the commands and output. 

 ![image](https://github.com/user-attachments/assets/5ce9d550-f38e-49d1-9f6a-e04cbea59b23)


Once the user has the base64 hash, the user can then go to Cyberchef on the internet and place this hash in the top portion of the table with the chosen hash. Then click on remove non-alphabet chars to make the output readable. The individual will then be able to see the packet capture in plaintext as the following screenshot below shows. 


![image](https://github.com/user-attachments/assets/bee0341e-d289-45f6-ba7e-3937aa53b871)

 

There are other ways of finding passwords and other tools to use. For example, hashcat is a popular tool to use among penetration testers and hackers alike. Hashcat is a popular and effective password cracker widely used by both penetration testers and sysadmins as well as criminals and spies. At the most basic level, hashcat guesses a password, hashes it, then compares the resulting hash to the one its trying to crack. If the hashes match, we know the password. If not, it keeps guessing (Porup, 2020). Using the information provided, hashcat works using hashes such as Message Digest 5 (MD5) and numerous other Hashes in variations using a list of most common passwords that match the hashes for those passwords. Using the password found in the FTP transfer from the packet capture ‘sup4secure’ as the goal password. First, a list of passwords must be created. These are a long list of random passwords but can be found from websites like Github and added to the Kali Linux distribution to use. The most common word list is the Rockyou.txt file. Once the user has the wordlist of choice, next is to place all the hashes into another file for hashcat to cross reference all the passwords to the given hashes. In this example the hashes will be in the target.txt file and the wordlist will be the list.txt file. Additionally, the user can have Hashcat place the found hashes into another text file at the end of the command. Once the possible choices of passwords and hashes are in place the user can run the command, ‘hashcat -a 0 -m 0 (hash file) (word file) -o (match file)’ the final command can look similar to ‘hashcat -a 0 -m 0 target.txt list.txt -o cracked.txt’ as shown in the screenshot below. Hashcat will output an enormous amount of information this is why it is best to add a file to place anything found in. However, if not then the information that is needed is next to the Recovered section. 

![image](https://github.com/user-attachments/assets/c3846a5c-6146-4d5e-84eb-6438d9729797)

 
This can often be difficult to find or know which passwords were recovered. Therefore, it is suggested to have a file created with any found hashes sent to another file in the command as shown in the screenshot below. 
 
![image](https://github.com/user-attachments/assets/5ea6706f-c545-41f7-be58-a5fc31056bd7)


Conclusion

In conclusion, this lab displayed the importance of encryption of data in transit throughout a network. Without encryption over a network individuals can use tools like Wireshark to gain access to users credentials such as usernames and passwords with tools such as fcrackzip and hashcat. Overall, this lab showed a practical insight into the importance of secured ports and protocols and the consequences cybercriminals and other threat actors can do with simple techniques. 
