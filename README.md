> HTB Penetration Tester

# Penetration Testing Process 

##### Testing Methods 
- **External Penetration Test**
Many pentests are performed from an external perspective or as an anonymous user on the Internet. Most customers want to ensure that they are as protected as possible against attacks on their external network perimeter. We can perform testing from our own host (hopefully using a VPN connection to avoid our ISP blocking us) or from a VPS. Some clients don't care about stealth, while others request that we proceed as quietly as possible, approaching the target systems in a way that avoids firewall bans, IDS/IPS detection, and alarm triggers. They may ask for a stealthy or "hybrid" approach where we gradually become "noisier" to test their detection capabilities. Ultimately our goal here is to access external-facing hosts, obtain sensitive data, or gain access to the internal network.

- **Internal Penetration Test**
In contrast to an external pentest, an internal pentest is when we perform testing from within the corporate network. This stage may be executed after successfully penetrating the corporate network via the external pentest or starting from an assumed breach scenario. Internal pentests may also access isolated systems with no internet access whatsoever, which usually requires our physical presence at the client's facility.

- **Types of Penetration Testing**
- No matter how we begin the pentest, the type of pentest plays an important role. This type determines how much information is made available to us. We can narrow down these types to the following:


|Type |Information Provided |
|:- |:-|
|BlackBox |**Minimal**. Only the essential information, such as IP addresses and domains, is provided. |
|GrayBox |**Extended**. In this case, we are provided with additional information, such as specific URLs, hostnames, subnets, and similar. |
|WHiteBox |**Maximum**. Here everything is disclosed to us. This gives us an internal view of the entire structure, which allows us to prepare an attack using internal information. We may be given detailed configurations, admin credentials, web application source code, etc. |
|RedTeaming |May include physical testing and social engineering, among other things. Can be combined with any of the above types. |
|PurpleTeaming |It can be combined with any of the above types. However, it focuses on working closely with the defenders. |

- The less information we are provided with, the longer and more complex the approach will take. For example, for a blackbox penetration test, we must first get an overview of which servers, hosts, and services are present in the infrastructure, especially if entire networks are tested. This type of recon can take a considerable amount of time, especially if the client has requested a more stealthy approach to testing.

- **Types of Testing Environments**

|Type |Type |Type |Type |Type |
|:- |:-|:- |:-|:- |
| Network |	Web App |	Mobile |	API	| Thick Clients |
| IoT	| Cloud |	Source Code |	Physical Security |	Employees |
| Hosts |	Server | Security Policies |	Firewalls |	IDS/IPS |

##### Laws and Regulations
- Each country has specific federal laws which regulate computer-related activities, copyright protection, interception of electronic communications, use and disclosure of protected health information, and collection of personal information from children, respectively.
- It is essential to follow these laws to protect individuals from **unauthorized access** and **exploitation of their data** and to ensure their privacy. We must be aware of these laws to ensure our research activities are compliant and do not violate any of the provisions of the law. Failure to comply with these laws can result in civil or criminal penalties, making it essential for individuals to familiarize themselves with the law and understand the potential implications of their activities. Furthermore, it is crucial to ensure that research activities adhere to these laws' requirements to protect individuals' privacy and guard against the potential misuse of their data. By following these laws and exercising caution when conducting research activities, security researchers can help ensure that individuals' data is kept secure and their rights are protected. 

![Laws and Regulations](/Images/Laws_Regulations.png)

##### Precautionary Measure

- [ ] (Obtain written consent from the owner or authorized representative of the computer or network being tested)
- [ ] (Conduct the testing within the scope of the consent obtained only and respect any limitations specified)
- [ ] (Take measures to prevent causing damage to the systems or networks being tested)
- [ ] (Do not access, use or disclose personal data or any other information obtained during the testing without permission)
- [ ] (Do not intercept electronic communications without the consent of one of the parties to the communication)
- [ ] (Do not conduct testing on systems or networks that are covered by the Health Insurance Portability and Accountability Act (HIPAA) without proper authorization)

#### Penetration Testing Stages

![Penetration Testing Phases](/Images/PenetrationTestingProcess_Overview.png)
- **Pre-Engagement**
Pre-engagement is educating the client and adjusting the contract. All necessary tests and their components are strictly defined and contractually recorded. In a face-to-face meeting or conference call, many arrangements are made, such as:
    - Non-Disclosure Agreement
    - Goals
    - Scope
    - Time Estimation
    - Rules of Engagement
- **Information Gathering**
Information gathering describes how we obtain information about the necessary components in various ways. We search for information about the target company and the software and hardware in use to find potential security gaps that we may be able to leverage for a foothold.

- **Vulnerability Assessment**
Once we get to the Vulnerability Assessment stage, we analyze the results from our Information Gathering stage, looking for known vulnerabilities in the systems, applications, and various versions of each to discover possible attack vectors. Vulnerability assessment is the evaluation of potential vulnerabilities, both manually and through automated means. This is used to determine the threat level and the susceptibility of a company's network infrastructure to cyber-attacks.

- **Exploitation**
In the Exploitation stage, we use the results to test our attacks against the potential vectors and execute them against the target systems to gain initial access to those systems.

- **Post-Exploitation**
At this stage of the penetration test, we already have access to the exploited machine and ensure that we still have access to it even if modifications and changes are made. During this phase, we may try to escalate our privileges to obtain the highest possible rights and hunt for sensitive data such as credentials or other data that the client is concerned with protecting (pillaging). Sometimes we perform post-exploitation to demonstrate to a client the impact of our access. Other times we perform post-exploitation as an input to the lateral movement process described next.

- **Lateral Movement**
Lateral movement describes movement within the internal network of our target company to access additional hosts at the same or a higher privilege level. It is often an iterative process combined with post-exploitation activities until we reach our goal. For example, we gain a foothold on a web server, escalate privileges and find a password in the registry. We perform further enumeration and see that this password works to access a database server as a local admin user. From here, we can pillage sensitive data from the database and find other credentials to further our access deeper into the network. In this stage, we will typically use many techniques based on the information found on the exploited host or server.

- **Proof-of-Concept**
In this stage, we document, step-by-step, the steps we took to achieve network compromise or some level of access. Our goal is to paint a picture of how we were able to chain together multiple weaknesses to reach our goal so they can see a clear picture of how each vulnerability fits in and help prioritize their remediation efforts. If we don't document our steps well, it's hard for the client to understand what we were able to do and, thus, makes their remediation efforts more difficult. If feasible, we could create one or more scripts to automate the steps we took to assist our client in reproducing our findings. We cover this in-depth in the Documentation & Reporting module.

- **Post-Engagement**
During post-engagement, detailed documentation is prepared for both administrators and client company management to understand the severity of the vulnerabilities found. At this stage, we also clean up all traces of our actions on all hosts and servers. During this stage, we create the deliverables for our client, hold a report walkthrough meeting, and sometimes deliver an executive presentation to target company executives or their board of directors. Lastly, we will archive our testing data per our contractual obligations and company policy. We will typically retain this data for a set period or until we perform a post-remediation assessment (retest) to test the client's fixes.

- **Importance**
We must internalize this procedure and use it as a basis for all our technical engagements. Each stage's components allow us to precisely understand which areas we need to improve upon and where most of our difficulties and gaps in knowledge are. For example, we can think of a website as a target we need to study.

|Type |Description |
|:- |:-|
|Pre-Engagement | The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions. |
|Information Gathering | Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions. |
| Vulnerability Assessment | With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions. |
| Exploitation | Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities. |
|Post Exploitation |Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations). |
|Lateral Movement | If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered.|
|Proof of Concept | We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities.|
| Post Engagement | Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings. |

#### Pre-Engagement
- Mainly deals with engaging with client and NDA(Non Disclosure Aggrement), what type test to conduct date and time, Place, duration.
- Have this 7 documents

|S.No|Document |Time of Creation |
|:-|:- |:- |
|1|Non-Disclosure Agreement (NDA) |**After** Initial Contact |
|2|Scoping Questionnaire | **Before** the Pre-Engagement Meeting|
|3|Scoping Document | **During** the Pre-Engagement Meeting|
|4|Penetration Testing Proposal (Contract/Scope of Work (SoW)) |**During** the Pre-engagement Meeting |
|5|Rules of Engagement (RoE) |**Before** the Kick-Off Meeting |
|6|Contractors Agreement (Physical Assessments) |**Before** the Kick-Off Meeting |
|7|Reports |**During** and **after** the conducted Penetration Test |

#### Information Gathering
- All steps we take in this phase information we enumerate used to exploit the target, This phase considered as most important of any penetration testing.
- We can obtain this information many differant ways, We can divide into majorly 4 types
- Open-Source Intelligence
    - OSINT mostly focuses on publicly avaliable information in the internet, company portal github repositorues have some sensitive informatio like SSH keys, tokens often developer leave the code samples in stackoverflow
- Infrastructure Enumeration
    - Identifying company position on internet and intranet which includes Name, Mail, Web, Cloud instance identify the firewall positions
- Service Enumeration
    - Identify the service that allows you to communicate over the internet or internet, what type version and information provdies to us and reason to us, Many administrators afrid to chnag the service upgrades due working application they should often accept leaving one or more vulnerabilites maintaining the functionality instead of closing the security gaps.
- Host Enumeration
    - Once we have the detailed list of customers start enumerating host which type OS, misconfiguration, services running the host now a days most OS vendors not providing the support to that, how the employees are comunicating protocol SSH, anonymous logins, Ports and what kind of data storing in the host machines will useful in Post-Exploitaion step it useful privilege escalation.
- Pillaging
    - Pillaging another essential step after performing these steps we have some information like credentials details which is used for Post-Exploitation.

#### Vulnerability Assessment
- We examine and analyze the the inforamtion gathered during information gathering phase, This VA analytical process based on the findings.
>An analysis is a detailed examination of an event or process, describing its origin and impact, that with the help of certain precautions and actions, can be triggered to support or prevent future occurrences.

|Analysis Type |Description |
|:- |:- |
|Descriptive |Descriptive analysis is essential in any data analysis. On the one hand, it describes a data set based on individual characteristics. It helps to detect possible errors in data collection or outliers in the data set. |
|Diagnostic |Diagnostic analysis clarifies conditions' causes, effects, and interactions. Doing so provides insights that are obtained through correlations and interpretation. We must take a backward-looking view, similar to descriptive analysis, with the subtle difference that we try to find reasons for events and developments. |
|Predictive |By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible. |
|Prescriptive |Prescriptive analytics aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process. |

- If any random port is open like TCP 2121, is essential to ask precise question what we know and don't know, We our self what we see what actually have 
    - a TCP port 2121. - TCP already means that this service is connection-oriented.
    - Is this a standard port? - No, because these are between 0-1023, aka well-known or system ports
    - Are there any numbers in this port number that look familiar? - Yes, TCP port 21 (FTP). From our experience, we will get to know many standard ports and their services, which administrators often try to disguise, but often use "easy to remember" alternatives.

- **Vulnerability Research and Analysis**
    - **Information Gathering** and **Vulnerability Research** can be considered as descriptive analysis, Identify the indivudual network or a system component your investigating. In **Vulnerability Research** we look for known vulnerability, exploit and security holes already discovered and reported in public.
        - Exploit DB
        - CVE Details
        - Vulners
        - Packet Storm Security
        - NIST

#### Exploitation
- During the Exploitation stage we llok for the weakness can be adapted to our case to obtain the desired role including the foodhold, Privilege Escalation. If want get a reverse shell, we need to modify the PoC to execute the code, so that that system that connect back to over (ideally) encryption connection to an IP address, This kind of preparation mainly prt of the Exploitation satge.

- **Prioritization of Possible Attacks**
    - propability of Success
        - Executing the particular attack against the target. Using [CVSS Scoring](https://nvd.nist.gov/vuln-metrics/cvss) can be help us, Using [NVD Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) better calculate the specific attack and propability of Success
    - Complexity
        - It represnts the effort exploiting of a specific vulnerability, This can be estimated how much of time, effort and research your putting to exploiting, you never exploited this particular vulnerability before, logically require much time to research and setup indetail before understanding the vulnerability.
    - Propability of Damage
        - Estimating propability of Damege caused by the execution of an exploit palys a crucial role, we must avoid damege to the target system, Generally DoS attack unless client. Nevertheless, attacking the running service or OS something likethat must avoid.

- Prioritization Example
    - Based on the Below example, we would prefer the remote file inclusion attack. It is easy to prepare and execute and should not cause any damage if approached carefully.

 |Factor |Points |Remote File Inclusion | Beffer Overflow |
 |:-|:-|:-|:-|
 |1. Probability of Success |10 | 10|8 |
 |2. Complexity - Easy |5 |4 |0 |
 |3. Complexity - Medium | 3| 0| 3|
 |4. Complexity - Hard |1 |0 |0 |
 |5. Probability of Damage |-5 | |-5 |
 | Summary|Max .15 | 14|6 |

 - Preparation for the Attack
    - Sometime we will run into a situation where we can't find high-quality, known working PoC exploit code. Therefore, it may be necessary reconstruct the exploit locally on a VM our target host to figureout whats needs to adapted and changed, Once we have set up the system locally and installed known components to mirror the target environment as closely as possible (i.e., same version numbers for target services/applications), The exploit works but does not damge system significanly so we must consider any other the misconfigaration must communicate with TeamLead/Manager about the issue, before exploiting the target first inform issue with client weather they want to proceed with the attack or make it vulnerability in the report with exploiting.

#### Post-Exploitation
- Let's assume we successfully exploited target system during the exploitation stage, Afterthat we must consider the whether or not consider **Evasive Testing** in the Post-Exploitation stage amis sensitive information, local perspective, Business-relevent information in most cases requires higher privileges then the standard user. 
- The stage includes following components
    - Evasive Testing
    - Information Gathering
    - Pillaging
    - Vulnerability Assessment
    - Privilege Escalation
    - Persistence
    - Data Exfiltration
- Evasive Testing 
    - a type of security testing where attackers or ethical hackers try to bypass security measures, like firewalls and intrusion detection systems, to gain unauthorized access to a system or application. 
    - Whatever the activity we do that it will be monitered commands like whoami, user those flagged in the system monitering and SOC EDRs
    
