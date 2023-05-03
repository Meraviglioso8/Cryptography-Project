# A MULTI-FACTOR AUTHENTICATION-BASED IN CLOUD APPLICATIONS #

## 1. **Abstract** ##

 A security mechanism is applied to the cloud application that includes
user registration, granting user privileges, and generating user authentication factor. An intrusion detection system is embedded to the security mechanism to detect malicious users. The multi factor authentication, intrusion detection, and access control techniques can be used for ensuring the identity of the user.

## 2. **Motivation** ##
User’s data is considered as a vital asset of several organizations. Migrating data to the cloud computing is not an easy decision for any
organization due to the privacy and security concerns. Service providers must ensure that both data and applications that will be stored on the cloud should be protected in a secure environment. The data stored on the public cloud will be vulnerable to outside and inside attacks.



## 3. **Scenario** ##


![Untitled Diagram-Page-1 drawio](https://user-images.githubusercontent.com/46748862/235931848-115d51fc-868a-4438-b1e4-11887a1d2710.png)



## 4. **Proposed Solution** ##
4.1. **Solution**

![demo plan drawio (3)](https://user-images.githubusercontent.com/46748862/235932145-15f67b02-f606-406d-94f9-e546e177b874.png)


4.2. **Demo Architecture**


![Untitled Diagram-Copy of Page-1 drawio](https://user-images.githubusercontent.com/46748862/235932162-dbc30f5c-cbe7-4e8b-8fe5-a2acc593ea9c.png)

4.3. **Security Goals**

![sECURITYGOAL-Copy of Page-1 drawio (1)](https://user-images.githubusercontent.com/46748862/235932325-87f2d891-ef6a-40d1-97ce-185426f257c0.png)

4.3. **Research Goals**

![sECURITYGOAL-Copy of Page-1 drawio](https://user-images.githubusercontent.com/46748862/235932400-960e7471-16bb-4196-b65b-06b3b0637def.png)

## 5. **Summary** ##

|**OBJECTS**|**SPECIFICATION**|
| :-: | :-: |
|**Protected Assets**|**Private Message, File transferred…**|
|**Parties**|**MANET’s Users (Data owner)**|
|**Security Goal**|<p>**Authentication for a transfer session,**</p><p>**Validating the integrity of transferred data**</p><p>**Confidentiality for transferred data**</p>|
|**Algorithm**|**SHA-256, SHA-512**|

5.1. **Tools** 
|**TOOLS**|**SPECIFICATION**|
| :-: | :-: |
|**Python**|Use for algorithm|
|**PyCrypto**|Use for algorithm|
|**C# and DotNet**|Use for interface, backend|
|**Microsoft SQL**|Use for database management|
|**Git**|Use for version control system|
|**INET framework/Network Attack (NETA)**|Use for simulating MANET environment and test authentication mechanism  |
|**Security Libraries (E.g.: Bouncy Castle, OpenSSL )**|Use for implementing some cryptography functions|
- **Hardware Resources:** Laptop, Smartphone.
- **Optional Hardware Resources:** Switch, router, … (Base on real situation).

5.2 **Task assignment**
|**TASK**|**SPECIFICATION**|**MEMBER**|
| :-: | :-: | :-: |
|**Research on MANET**|Familiarize yourself with the concept of Mobile Ad-hoc Networks (MANET) and how it works|Team|
|**Research on mutual authentication**|Study mutual authentication in computer networks and how it can be implemented in MANET. In this case is session token with finger print and mac address validation|Team|
|**Design the system pattern**|Develop a system design that includes the details of the mutual authentication protocol. This includes the use of session tokens, fingerprint validation, and MAC address validation.|Huyền|
|**Develop the application (Some of features)**|Develop an application that can be used to simulate the MANET environment|Hưng|
|**Implement the mutual authentication protocol(Hope we can make this far ^^)**|Implement the mutual authentication protocol using the application which was developed. This includes the generation of session tokens, the validation of fingerprints and MAC addresses, and the exchange of authentication messages between nodes.|Kiệt|
|**Conduct testing**|Test the implemented protocol to ensure it works as expected|Hưng|
|**Evaluate and analyze the results**|Analyze the results of the testing to determine the efficiency and effectiveness of the implemented mutual authentication protocol|Kiệt|
|**Write the project report**|Write a comprehensive report of the project, which should include the system design, implementation, and testing results, as well as any relevant observations, conclusions, and recommendations.|Huyền|
|**Submit the project and presentation**||Team|

5.3 **Contribution**
|**Student ID**|**Name**|
| :-: | :-: |
|21520269|Trần Thị Mỹ Huyền|
|21520903|Trương Long Hưng|
|21521034|Ngô Tuấn Kiệt|

5.4 **References**

- 1\. Bairwa, A. K., & Joshi, S. (2021). Mutual authentication of nodes using session token with fingerprint and MAC address validation. Egyptian Informatics Journal, 22(4), 479–491. 
- 2\. Al-Shareeda, M. A., & Manickam, S. (2022). Man-in-the-Middle Attacks in Mobile Ad Hoc Networks (MANETs): Analysis and Evaluation. Symmetry, 14(8), 1543. 
- 3\. Bhattacharyya, A., Banerjee, A., Bose, D., & Bhattacharyya, D. (2011, November 17). Different types of attacks in Mobile ADHOC Network. ResearchGate. 
- 4\. Abass, R., Habyarimana, A., & Tamine, K. (2022). Securing a mobile ad hoc NETwork against the man in the middle attack. International Journal Artificial Intelligent and Informatics, 3(1), 53–62. 
