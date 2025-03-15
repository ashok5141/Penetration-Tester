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