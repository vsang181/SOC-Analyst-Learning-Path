# Introduction to SOC (Security Operations Center)

## What we will learn?
- The structure of a SOC
- The operation of a SOC
- SOC Tools/Products
- How a SOC Analyst should use his tools
- Frequent mistakes that SOC Analysts make

***
***

# SOC Types and Roles

## What is a SOC?

A **Security Operation Center (SOC)** is a facility where the information security team continuously monitors and analyzes an organization's security posture. The main goal of the SOC team is to detect, analyze, and respond to cybersecurity incidents using a combination of technology, people, and processes.

## Types Of SOC Models

![image](https://github.com/vsang181/SOC-Analyst-Learning-Path/assets/28651683/2e608425-f5e9-45e2-9d26-d592f411a33e)
   
Organizations may choose different SOC models based on their security requirements and budget:   
   
### 1. In-house SOC

- **Description**: The enterprise builds its own cybersecurity team, requiring a significant budget for continuity.

### 2. Virtual SOC

- **Description**: The security team operates remotely from various locations, without a dedicated physical facility.

### 3. Co-Managed SOC

- **Description**: Combines internal SOC personnel with an external Managed Security Service Provider (MSSP), emphasizing the importance of coordination.

### 4. Command SOC

- **Description**: A senior group that oversees smaller SOCs across a large region, often used by major telecom providers and defense agencies.

## People, Process, and Technology in SOC

### People

- Essential to have highly trained personnel who are familiar with security alerts and attack scenarios and can adapt to new types of attacks through research.

### Processes

- Aligning the SOC structure with security requirements like NIST, PCI, and HIPAA is crucial, requiring extreme standardization to ensure thoroughness.

### Technology

- Requires a range of products for penetration testing, detection, prevention, and analysis, with a need to stay updated on market and technology trends.

## SOC Positions

### SOC Analyst

- **Roles**: Classified into Level 1, 2, and 3. They classify alerts, investigate causes, and recommend remedial actions.

### Incident Responder

- **Roles**: Participates in threat detection and performs initial assessments of security breaches.

### Threat Hunter

- **Roles**: Proactively seeks and investigates potential threats using both manual and automated techniques to detect and mitigate advanced threats.

### Security Engineer

- **Roles**: Maintains the security infrastructure, including connections between SIEM and SOAR products.

### SOC Manager

- **Roles**: Manages budgeting, strategizing, personnel, and operations, focusing on operational aspects.

## Conclusion

The effective operation of a SOC hinges on the successful integration of people, processes, and technology, alongside the choice of an appropriate SOC model that fits the organization's needs and budget constraints.

***
***

# SOC Analyst and Their Responsibilities

## Introduction

Understanding the role and responsibilities of a SOC (Security Operations Center) Analyst is crucial for candidates aspiring to pursue a career in this field. This section provides insight into the life, advantages, and competencies required for a SOC analyst.

## What is a SOC Analyst?
A SOC Analyst stands as the frontline defense of an organization's cybersecurity efforts. They are the first to analyze threats against the system and play a pivotal role in escalating incidents to seniors for effective threat mitigation.

## The Advantages of Being a SOC Analyst
- **Variety of Incidents**: With the constant evolution of attack vectors and malware, SOC analysts enjoy a diverse range of incidents to investigate, ensuring the job remains engaging and far from monotonous.
- **Dynamic Environment**: The use of consistent operating systems and security products does not dull the role, as each incident presents its unique challenges and learning opportunities.

## A Day in the Life of a SOC Analyst
- **Alert Examination**: The day typically involves examining alerts on the SIEM system to determine real threats.
- **Utilizing Security Products**: Tools such as EDR (Endpoint Detection and Response), Log Management, and SOAR are employed to aid in threat analysis and conclusion.

## Competencies Required for a Successful SOC Analyst
1. **Operating Systems**
   - Understanding the basic logic of Windows/Linux operating systems is essential to differentiate normal from abnormal activities.
   
2. **Network**
   - Handling malicious IPs and URLs, checking for network connections to these addresses, and detecting potential data leaks require basic networking knowledge.

3. **Malware Analysis**
   - Analyzing malicious software to understand its purpose and behavior, including identifying command and control centers and communication with malicious addresses.

## Conclusion
Becoming a SOC Analyst requires not just familiarity with security products but also a deep understanding of operating systems, networking, and malware analysis. This foundation enables analysts to effectively analyze SIEM alerts and contribute significantly to their organization's cybersecurity efforts.

***
***

# SIEM and the SOC Analyst Relationship

## What is SIEM?
SIEM (Security Information and Event Management) is a cybersecurity solution that provides real-time event logging and analysis to detect security threats. Key features of SIEM for SOC analysts include:
- **Data Filtering**: SIEM solutions filter collected data to identify suspicious events.
- **Alert Creation**: Rules and filters are applied to identify activities that exceed predefined threshold values, triggering alerts for potential threats.

**Example Alert Scenario**: An alert could be triggered by 20 incorrect password attempts on a Windows operating system within 10 seconds, indicating suspicious activity.

![image](https://github.com/vsang181/SOC-Analyst-Learning-Path/assets/28651683/0b545539-67a0-4304-bc9a-aad3067a3572)

**Popular SIEM Solutions**: IBM QRadar, ArcSight ESM, FortiSIEM, Splunk, etc.

## Relationship Between a SOC Analyst and SIEM
While SIEM solutions offer a range of features, SOC analysts primarily focus on monitoring and analyzing alerts. The process involves:
- **Alert Analysis**: Analysts begin their role in the SOC by determining whether an alert represents a real threat or a false alarm.
- **Investigation Process**: Utilizing SOC products like EDR, Log Management, and Threat Intelligence Feeds, analysts investigate alert details to ascertain their legitimacy.
- **Team Coordination**: Alerts are managed through a "Main Channel" for shared visibility, with analysts taking ownership of alerts for investigation, thereby streamlining the team's response to threats.

>Quick Tip: A proficient SOC Analyst can identify false alerts, providing valuable feedback to enhance the SOC team's efficiency. For instance, an overly broad SIEM rule might trigger an alert for benign activities, such as a Google search containing the keyword "union" potentially mistaken for SQL Injection attempts.

## Final Words
We've explored the significance of SIEM in a SOC environment, emphasizing its utility for SOC Analysts in threat detection and analysis. The relationship between SOC analysts and SIEM technology is fundamental to identifying and responding to cybersecurity incidents efficiently.

## Conclusion
SIEM plays a pivotal role in the SOC ecosystem, serving as a crucial tool for SOC analysts in monitoring, analyzing, and responding to cybersecurity threats. Understanding and effectively managing this relationship is key to ensuring robust cybersecurity defense mechanisms.

***
***

# Log Management for SOC Analysts

## Introduction
As a SOC Analyst, log analysis is a fundamental part of your role. Understanding how to navigate and utilize Log Management systems effectively is crucial, regardless of the specific product brand used.

## What is Log Management?
Log Management is a solution that enables centralized access to various logs within an environment, such as web logs, operating system logs, firewall, proxy, and EDR logs. This centralization improves usability and efficiency by allowing for the management of these logs from a single point.

- **Key Benefit**: Centralizing log access reduces the margin of error and the time required for analysis by allowing a single query to replace multiple queries across various devices.

## Purpose of Log Management
The primary uses of Log Management for SOC Analysts include:

1. **Communication Checks**: To verify if there is any communication with a certain address and to detail this communication. For example, identifying devices attempting to communicate with a known command and control center like "letsdefend.io".

2. **Incident Investigation**: In case of an alert indicating data leakage to a suspicious IP address, Log Management helps in identifying if other devices are also communicating with the suspicious IP, aiding in a comprehensive investigation.

## Effective Use of Log Management
- **Centralized Log Sources**: On platforms like LetsDefend, you can find various log sources (e.g., Proxy, Exchange, Firewall) listed under "Type", indicating that these logs are collected in one place for easy access.

- **Scenario-Based Analysis**: Whether it's investigating malware communication or probing for data leaks to suspicious IPs, Log Management provides a streamlined approach to analyze relevant logs.

## Example Workflow
1. **Detecting Malware Communication**: Upon identifying malware that communicates with "letsdefend.io", use Log Management to search for any devices in your network attempting to connect with this command control center.

2. **Investigating Data Leakage**: Following an alert about data leakage to IP address 122.194.229.59, use Log Management to investigate whether other devices are also sending data to this suspicious IP.

## Conclusion
Log Management is an indispensable tool for SOC Analysts, enabling efficient and effective analysis of log data across various sources. Mastery of Log Management systems facilitates a deeper understanding of security incidents and enhances the capability to respond to threats accurately and swiftly.

***
***

# EDR - Endpoint Detection and Response

## What is EDR?
EDR is an integrated endpoint security solution designed for real-time continuous monitoring and collection of endpoint data, coupled with rules-based automated response and analysis capabilities. It's crucial for identifying, investigating, and responding to cybersecurity threats at the endpoint level.

- **Definition Source**: McAfee

## Analysis with EDR
Popular EDR solutions include CarbonBlack, SentinelOne, and FireEye HX, which offer various functionalities to support SOC Analysts in their roles.

### Key Features of EDR:
- **Endpoint Device Listing**: Displays accessible endpoint devices, allowing analysts to search for endpoints or conduct searches using Indicators of Compromise (IOC).
- **Detailed Device Information**: Provides information about the device and sections like "Browser History", "Network Connections", and "Process List" for thorough investigation.
- **Live Investigation**: Enables analysts to connect directly to the machine for continued analysis.

## Containment
A critical function of EDR solutions is the ability to isolate compromised machines from both internal and external networks. This isolation prevents attackers from further penetrating the network while allowing the device to communicate only with the EDR center for ongoing analysis.

> Quick Tip: Utilize EDR to search across all hosts for any IOC, such as file hashes or names, to identify affected devices and understand the scope of an attack.

## Conclusion
EDR is as fundamental to SOC Analysts as Log Management, offering unique capabilities for endpoint security analysis and response. Spending time mastering EDR can significantly enhance an analyst's effectiveness and efficiency in responding to threats.

***
***

# SOAR (Security Orchestration Automation and Response)

## Introduction
SOAR stands for Security Orchestration Automation and Response, a technology that enables integration and automation of security tools and processes within an environment. It significantly eases the responsibilities of SOC team members by facilitating coordinated actions across various security solutions.

Some SOAR products frequently used within the industry:
- Splunk Phantom
- IBM Resilient
- Logsign
- Demisto

## Key Benefits of SOAR

### Time Efficiency
SOAR enhances operational efficiency through automated workflows for routine tasks, such as:
- IP address reputation checks
- Hash queries
- Scanning files in a sandbox environment

### Centralization
SOAR centralizes the operation of diverse security tools (e.g., Sandbox, log management systems, third-party tools), allowing for unified management and execution within a single platform.

### Playbooks
SOAR playbooks standardize response procedures for various scenarios, ensuring consistent analysis and actions across the SOC team. This standardization helps avoid discrepancies in response strategies, such as some team members omitting IP reputation checks.

## Utilizing SOAR in SOC Operations

### Integration with Security Products
SOAR platforms, like Splunk Phantom, IBM Resilient, Logsign, and Demisto, integrate with existing security products, automating actions like VirusTotal searches for SIEM alert source IPs, thereby reducing manual workload.

### Scenario-based Analysis
Through playbooks, SOC analysts can systematically investigate SIEM alerts, following predefined steps even without comprehensive knowledge of all procedures. This ensures thorough and uniform analysis across all team members.

## Conclusion
SOAR platforms play a critical role in modern SOC environments, automating routine tasks, centralizing tool operations, and standardizing response strategies. By leveraging SOAR, SOC analysts can significantly improve their efficiency and effectiveness in handling security incidents.


***
***

# Threat Intelligence Feeds in SOC Operations

For a Security Operations Center (SOC) team, staying updated with the latest threats is paramount. Threat Intelligence Feeds are designed to meet this requirement by providing data crucial for ongoing security investigations and preventative measures.

## What is a Threat Intelligence Feed?
A Threat Intelligence Feed delivers data related to cybersecurity threats, such as malware hashes, command and control (C2) domain/IP addresses, and other indicators of compromise (IOCs), usually provided by third-party companies.

### Key Features:
- **Data Types**: Includes hashes, IP addresses, and more, collected from past malicious activities.
- **Purpose**: Helps SOC analysts in identifying whether a specific file hash or IP address has been involved in malicious activities previously.

## Utilizing Threat Intelligence Feeds
Platforms like LetsDefend offer "Threat Intel" pages that showcase a variety of data points for SOC analysts to leverage during investigations.

### Popular Free Sources:
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [Talos Intelligence](https://talosintelligence.com/)

## Points of Caution

### Non-Detection in Feeds
- If a search through a Threat Intelligence Feed returns no suspicious history for an item (e.g., a file hash), it should not immediately be considered safe. Analysts must still perform comprehensive file analyses to determine its nature.

### Changing IP Ownership
- IP addresses can change ownership, meaning an IP once used for malicious purposes may later serve legitimate sites or services. Analysts must consider the current context of an IP address, not just its history in threat feeds.

## Conclusion
Threat Intelligence Feeds are invaluable resources for SOC teams, providing timely data on potential cybersecurity threats. However, SOC analysts must exercise caution and perform thorough investigations, recognizing the limitations and dynamics of threat intelligence data.

***
***

# Common Mistakes for SOC Analysts and How to Avoid Them

Even the most diligent SOC analysts can make mistakes. This section outlines common errors and provides guidance on how to avoid them, ensuring more effective and accurate cybersecurity operations.

## Common Mistakes

### Overly Depending on VirusTotal Results
- **Issue**: Sole reliance on VirusTotal for determining the safety of a file or URL.
- **Solution**: Treat VirusTotal as a supportive tool, not the definitive authority. Always conduct additional analyses to confirm findings.

### Hasty Analysis of Malware in a Sandbox
- **Issue**: Short sandbox analyses may not reveal the true nature of sophisticated malware.
- **Reasons**:
  - Malware detecting sandbox environments and remaining inactive.
  - Malware programmed to activate after prolonged periods.
- **Solution**: Extend the duration of sandbox analyses and, when possible, conduct them in real environments.

### Insufficient Log Analysis
- **Issue**: Failing to perform thorough log analyses, potentially overlooking indicators of compromise.
- **Solution**: Utilize log management solutions effectively to investigate all possible communication to and from suspicious addresses.

### Overlooking VirusTotal Dates
- **Issue**: Relying on cached results from VirusTotal without considering the date of the last analysis.
- **Solution**: Always initiate a new search rather than trusting outdated cache results. Attackers may exploit this by initially submitting clean URLs and later embedding malicious content.

![image](https://github.com/vsang181/SOC-Analyst-Learning-Path/assets/28651683/82a45de1-88d5-4918-b105-cddb259c0f31)

## Conclusion
Avoiding these common mistakes requires vigilance, a critical approach to tools and data, and a commitment to thorough investigation. By understanding and addressing these pitfalls, SOC analysts can enhance their effectiveness in identifying and mitigating cybersecurity threats.

> Remember, tools like VirusTotal are invaluable but should be used as part of a broader analytical process that includes deep log analysis, careful consideration of malware behavior, and awareness of the dynamic nature of cyber threats.

## Let's Connect

I welcome your insights, feedback, and opportunities for collaboration. Together, we can make the digital world safer, one challenge at a time.

- **LinkedIn**: (https://www.linkedin.com/in/aashwadhaama/)

I look forward to connecting with fellow cybersecurity enthusiasts and professionals to share knowledge and work together towards a more secure digital environment.
