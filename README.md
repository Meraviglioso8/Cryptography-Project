# MUTUAL AUTHENTICATION OF MANET’S NODES USING SESSION TOKEN WITH FINGERPRINT AND MAC ADDRESS VALIDATION #

## 1. **Abstract** ##

The mobile node’s property is dynamic, so it isn’t easy to manage security policies. These difficulties present a barrier to building multigene security arrangements that accomplish both assurance and attractive network execution. The proposed work suggests the mutual authentication-based protocol, helping in the handshake between two nodes. 

## 2. **Motivation** ##

Weak security in the MANET may cause the man in the middle attack, a significant security loophole. Dynamic attacks could perform by deleting messages, sending wrong messages, mimic a node, which causes breaking accessibility, trust, authentication, and serving the Denial of Services (DoS). Because of MANET’s physical limitations, security is an important area where several research works have been introduced, but the dynamic security system is still under process. The necessity of security systems should be dynamic and flexible to be salable. The MANET authentication can be categorized into three areas as data, node, and user level.



![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.001.png)










## 3. **Scenario** ##

When two nodes of MANET communicating, Man-In-The-Middle (MITM) attackers put legal nodes’ communications at risk by altering their messages. Such assaults have serious effects on the communication, particularly if the message’s content includes information about safety. MANET can meet two types of MITM attack: 

- **Passive Mode:** The communication line between legal nodes can be passively eavesdropped on by an attacker. 
- **Active Mode:** Attackers have the active capability to delay or drop the content of data that is received in a communication.


![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.002.png)











![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.003.png)









## 4. **Proposed Solution** ##
4.1. **Solution**

To prevent the MITM attacks, we propose **a** mutual authentication, which usually offer to protect against MITM attacks but using **session token with fingerprint and MAC address validation.**

![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.004.png)












![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.005.png)

![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.006.png)







![](img/Aspose.Words.c47eb186-4645-4f67-9718-f333edaa321d.007.png)

4.2. **The objective of work**

1\. In the mutual authentication based protocol, the MAC address and fingerprint will form the basis of the determination of node, which is the dual authentication basis of node identification. 

2\. Randomization session for transfer by the Generation of Token. Each time the transfer occurs, a new session token is required to be generated to provide more security in the data transfer. To repeat the token generation process, the communicating nodes’ MAC addresses will be needed in the token generation process. 

3\. Dual Security in the data transfer with the generation of OTP and Transaction ID for the receiver’s validation. 

4\. Validating the integrity of the data received with the Hash generation for the message received and comparing it with the hash sent.

4.3. **Algorithm**

The proposed algorithm is the joint or associated algorithm that performs the work based on the sub-algorithms, which are used in the process are as follows: 

- Registering the User in Network  
- Destination MAC Address Validation  
- Generation of Token for Message Exchange  
- Module for Sender End  
- Module for Receiver
1. **Algorithm 1: Algorithm for Registration**

**Input:** MAC Address, Fingerprint 

**Output:** Success and Details of node Saved, Unique node Number Generated 

2. **Algorithm 2: Destination MAC Address Validation**

**Input:** Destination node Number. 

**Output:** Success Return MAC Address of node. 

3. **Algorithm 3:** Generation of Token for Message Exchange

**Input:** Sender MAC Address, Destination MAC Address 

**Output**: SESSION\_TOKEN

4. **Algorithm 4:** Module for Sender End

**Input:** Sender MAC Address, Destination MAC Address, SESSION\_TOKEN 

**Output:** OTP and Transaction ID 

5. **Algorithm 5:** Module for Receiver 

**Input:** Sender MAC Address, Destination MAC Address, OTP, Transaction ID 

**Output:** Message Decrypted, Success



## 5. **Summary** ##

|**OBJECTS**|**SPECIFICATION**|
| :-: | :-: |
|**Protected Assets**|**Private Message, File transferred…**|
|**Parties**|**MANET’s Users (Data owner)**|
|**Security Goal**|<p>**Authentication for a transfer session,**</p><p>**Validating the integrity of transferred data**</p>|
|**Algorithm**|**SHA-256, SHA-512**|
5.1. **Tools** 

|**TOOLS**|**SPECIFICATION**|
| :-: | :-: |
|**Python**|Use for algorithm|
|**PyCrypto**|Use for algorithm|
|**C# and DotNet**|Use for interface, backend|
|**Microsoft SQL**|Use for database management|
|**Git**|Use for version control system|
|**NS3/GNS3**|Use for simulating MANET environment and test authentication mechanism  |
|**Security Libraries (E.g.: Bouncy Castle, OpenSSL )**|Use for implementing some cryptography functions|
- **Hardware Resources:** Laptop, Smartphone.
- **Optional Hardware Resources:** Switch, router, … (Base on real situation).

5.2 **Contribution**
|**Student ID**|**Name**|**Work**|
| :-: | :-: | :-: |
|21520269|Trần Thị Mỹ Huyền| |
|21520903|Trương Long Hưng| |
|21521034|Ngô Tuấn Kiệt| |
