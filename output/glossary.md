# Cybersecurity Knowledgebase

## 1 Threats

### 1.1 Phishing
**Description:** 
 A social engineering attack where attackers impersonate legitimate entities via email or messages.

**Examples:**
- Email asking to reset your bank password
- Fake invoice from Microsoft

**Mitigation:**
- Employee training to recognize phishing attempts
- Use email filtering and anti-phishing tools
- Enable multi-factor authentication (MFA)

### 1.2 Malware
**Description:** 
 Malicious software designed to disrupt, damage, or gain unauthorized access to systems.

**Examples:**
- Viruses, worms, trojans
- Ransomware encrypting files

**Mitigation:**
- Install and update antivirus/antimalware software
- Keep systems and software patched
- Avoid opening suspicious attachments or links

### 1.3 Ransomware
**Description:** 
 Malware that encrypts a victim's files and demands payment for the decryption key.

**Examples:**
- WannaCry attack encrypting hospital files
- Ryuk ransomware targeting enterprises

**Mitigation:**
- Regularly back up data offline or to secure cloud storage
- Patch vulnerabilities and keep software updated
- Train users to avoid suspicious links and attachments

### 1.4 Denial of Service (DoS)
**Description:** 
 An attack aiming to make a service unavailable by overwhelming it with traffic.

**Examples:**
- Flooding a website with traffic to crash it
- Sending malformed packets to disrupt services

**Mitigation:**
- Use network firewalls and intrusion prevention systems (IPS)
- Employ traffic filtering and rate limiting
- Use content delivery networks (CDNs) for load balancing

### 1.5 Man-in-the-Middle (MitM)
**Description:** 
 An attacker intercepts and possibly alters communications between two parties.

**Examples:**
- Eavesdropping on public Wi-Fi traffic
- Session hijacking between client and server

**Mitigation:**
- Use strong encryption protocols (HTTPS, TLS)
- Avoid unsecured public Wi-Fi or use VPN
- Implement strong authentication methods

### 1.6 SQL Injection
**Description:** 
 Inserting malicious SQL queries into input fields to manipulate databases.

**Examples:**
- Extracting user data from a database
- Deleting records or gaining admin access

**Mitigation:**
- Use prepared statements and parameterized queries
- Sanitize and validate all user inputs
- Employ web application firewalls (WAF)

### 1.7 Cross-Site Scripting (XSS)
**Description:** 
 Injecting malicious scripts into websites that run in other users' browsers.

**Examples:**
- Stealing cookies to hijack sessions
- Defacing web pages with injected code

**Mitigation:**
- Sanitize user inputs and encode output properly
- Use Content Security Policy (CSP) headers
- Keep web frameworks and libraries updated

### 1.8 Zero-Day Exploit
**Description:** 
 Exploiting a software vulnerability unknown to the vendor or not yet patched.

**Examples:**
- Attacks using unpatched OS vulnerabilities
- Exploiting new bugs in web browsers

**Mitigation:**
- Implement layered security defenses (defense-in-depth)
- Use behavior-based intrusion detection systems
- Apply patches promptly once available

### 1.9 Password Attack
**Description:** 
 Attempts to obtain or guess passwords to gain unauthorized access.

**Examples:**
- Brute force guessing
- Credential stuffing with leaked passwords

**Mitigation:**
- Enforce strong password policies
- Implement account lockouts after failed attempts
- Use multi-factor authentication (MFA)

### 1.10 Insider Threat
**Description:** 
 Threats from employees or contractors who misuse access intentionally or unintentionally.

**Examples:**
- Data theft by an employee
- Accidental data leaks

**Mitigation:**
- Implement least privilege access controls
- Monitor user activities and audit logs
- Conduct regular security awareness training

### 1.11 Advanced Persistent Threat (APT)
**Description:** 
 A prolonged and targeted cyberattack to steal data or surveil an organization.

**Examples:**
- Nation-state attacks on critical infrastructure
- Long-term spying campaigns

**Mitigation:**
- Employ threat intelligence and continuous monitoring
- Use network segmentation and strong access controls
- Maintain incident response plans and conduct drills

### 1.12 Botnet
**Description:** 
 A network of compromised computers controlled by an attacker.

**Examples:**
- Distributed Denial of Service (DDoS) attacks
- Sending spam emails from infected devices

**Mitigation:**
- Use endpoint protection and anti-malware tools
- Monitor network traffic for anomalies
- Keep devices patched and updated

### 1.13 Credential Stuffing
**Description:** 
 Using leaked username-password pairs to breach other accounts.

**Examples:**
- Automated login attempts on popular sites
- Using breached data to hijack accounts

**Mitigation:**
- Use multi-factor authentication (MFA)
- Monitor login attempts and unusual activities
- Educate users on password reuse risks

### 1.14 Social Engineering
**Description:** 
 Manipulating people into divulging confidential information.

**Examples:**
- Pretexting or impersonation calls
- Phishing emails asking for credentials

**Mitigation:**
- Conduct regular security awareness training
- Implement verification procedures for sensitive requests
- Use email filtering and anti-spam solutions

### 1.15 Data Breach
**Description:** 
 Unauthorized access and extraction of sensitive information.

**Examples:**
- Hacker stealing customer databases
- Leaking confidential company documents

**Mitigation:**
- Encrypt sensitive data at rest and in transit
- Monitor and log access to sensitive information
- Perform regular vulnerability assessments

### 1.16 Eavesdropping Attack
**Description:** 
 Intercepting network traffic to capture sensitive data.

**Examples:**
- Sniffing passwords over unsecured Wi-Fi
- Capturing unencrypted communications

**Mitigation:**
- Use strong encryption for communications (e.g., TLS)
- Avoid public Wi-Fi or use VPNs
- Implement network segmentation and monitoring

### 1.17 Rootkit
**Description:** 
 Malware that hides its presence and provides persistent privileged access.

**Examples:**
- Kernel-level rootkits hiding malware
- Persistent backdoors on infected systems

**Mitigation:**
- Use trusted boot and integrity verification tools
- Regularly scan systems with advanced malware detection
- Reinstall systems if rootkits are detected

### 1.18 Drive-By Download
**Description:** 
 Malware automatically downloaded when visiting a compromised website.

**Examples:**
- Visiting a hacked site triggers ransomware download
- Hidden exploits in ads or scripts

**Mitigation:**
- Keep browsers and plugins updated
- Use web filtering and block malicious sites
- Employ endpoint protection and real-time scanning

### 1.19 Exploit Kit
**Description:** 
 Automated tools used to identify and exploit vulnerabilities on a victim's device.

**Examples:**
- Kits delivered through malicious websites
- Used to deploy ransomware or spyware

**Mitigation:**
- Patch systems and software regularly
- Use network monitoring and intrusion prevention
- Educate users about risky websites

### 1.20 Spam
**Description:** 
 Unsolicited bulk messages often used to deliver phishing or malware.

**Examples:**
- Unwanted marketing emails
- Spam containing malicious links

**Mitigation:**
- Use spam filters and email authentication (SPF, DKIM)
- Educate users to avoid clicking suspicious emails
- Implement rate limiting and blacklists

### 1.21 Watering Hole Attack
**Description:** 
 Compromising a trusted website frequently visited by targets to deliver malware.

**Examples:**
- Infecting a popular industry forum to target visitors

**Mitigation:**
- Use threat intelligence to monitor trusted sites
- Employ endpoint protection with behavior detection
- Educate users to verify unexpected website behavior

### 1.22 Session Hijacking
**Description:** 
 Taking over a valid user session to gain unauthorized access.

**Examples:**
- Stealing session cookies via XSS
- Man-in-the-middle attacks capturing tokens

**Mitigation:**
- Use secure cookies with HttpOnly and Secure flags
- Implement session timeouts and re-authentication
- Use encryption for data transmission

### 1.23 Keylogger
**Description:** 
 Malware or hardware that records keystrokes to steal sensitive information.

**Examples:**
- Software keyloggers capturing passwords
- Hardware devices plugged between keyboard and PC

**Mitigation:**
- Use endpoint protection and anti-malware software
- Avoid installing untrusted software
- Use virtual keyboards or two-factor authentication

### 1.24 DNS Spoofing
**Description:** 
 Altering DNS records to redirect traffic to malicious sites.

**Examples:**
- Redirecting bank website requests to phishing sites

**Mitigation:**
- Use DNSSEC to validate DNS data
- Monitor DNS traffic for anomalies
- Educate users on verifying website URLs

### 1.25 Clickjacking
**Description:** 
 Trick users into clicking hidden or disguised elements on a webpage.

**Examples:**
- Clicking a hidden “Like” button on a malicious page

**Mitigation:**
- Implement X-Frame-Options HTTP headers
- Use Content Security Policy (CSP)
- Educate users on suspicious webpage behavior

### 1.26 Typosquatting
**Description:** 
 Registering domain names similar to legitimate ones to trick users.

**Examples:**
- Using “goggle.com” instead of “google.com”

**Mitigation:**
- Educate users to verify URLs carefully
- Use browser filters and anti-phishing tools
- Monitor and block typosquatting domains

### 1.27 Cryptojacking
**Description:** 
 Unauthorized use of a device’s resources to mine cryptocurrency.

**Examples:**
- Malicious scripts running in browser to mine coins

**Mitigation:**
- Use ad blockers and script blockers
- Keep software patched and updated
- Use endpoint protection with behavior monitoring

### 1.28 Supply Chain Attack
**Description:** 
 Targeting software or hardware supply chains to inject malicious code.

**Examples:**
- Compromised software updates distributing malware

**Mitigation:**
- Verify software and hardware integrity
- Use trusted vendors and code signing
- Monitor software behavior and network activity

### 1.29 Password Spraying
**Description:** 
 Trying common passwords against many accounts to avoid lockouts.

**Examples:**
- Using “Password123” across multiple accounts

**Mitigation:**
- Enforce strong password policies
- Monitor for unusual login attempts
- Use multi-factor authentication (MFA)

### 1.30 Brute Force Attack
**Description:** 
 Systematically trying all possible password combinations.

**Examples:**
- Automated tools guessing passwords rapidly

**Mitigation:**
- Use account lockout policies
- Enforce complex password requirements
- Employ MFA and rate limiting

### 1.31 Rogue Software
**Description:** 
 Fake or malicious software pretending to be legitimate.

**Examples:**
- Fake antivirus that actually installs malware

**Mitigation:**
- Download software only from trusted sources
- Use endpoint protection
- Educate users on software authenticity

### 1.32 Eavesdropping (Sniffing)
**Description:** 
 Capturing unencrypted network traffic.

**Examples:**
- Packet sniffers on unsecured Wi-Fi networks

**Mitigation:**
- Use encryption protocols (TLS, VPN)
- Avoid using open Wi-Fi networks
- Monitor network traffic for suspicious activity

### 1.33 Social Media Attack
**Description:** 
 Exploiting social media platforms to spread malware or phishing.

**Examples:**
- Fake friend requests leading to malware links

**Mitigation:**
- Educate users about social media security
- Use privacy settings to limit exposure
- Use URL scanning tools before clicking links

### 1.34 Malvertising
**Description:** 
 Using online advertisements to spread malware.

**Examples:**
- Ads delivering drive-by downloads

**Mitigation:**
- Use ad blockers
- Employ endpoint protection
- Keep browsers and plugins updated

### 1.35 IoT Attack
**Description:** 
 Exploiting vulnerabilities in Internet of Things devices.

**Examples:**
- Using unsecured cameras as botnet nodes

**Mitigation:**
- Change default passwords on IoT devices
- Keep firmware updated
- Segment IoT devices on separate networks

### 1.36 Password Reset Attack
**Description:** 
 Exploiting password reset mechanisms to hijack accounts.

**Examples:**
- Answering security questions or intercepting reset emails

**Mitigation:**
- Use multi-factor authentication
- Implement strong verification for resets
- Monitor reset activity logs

### 1.37 Business Email Compromise (BEC)
**Description:** 
 Fraudulent emails impersonating executives to initiate wire transfers or data theft.

**Examples:**
- Fake CFO emails requesting urgent fund transfers

**Mitigation:**
- Implement email authentication (DMARC, SPF, DKIM)
- Verify requests via alternate channels
- Educate employees on BEC tactics


-----------------------------------------------------------------------------------------------------------------------------------------------------
## 2 Tools

### 2.1 Wireshark
**Description:** 
 A powerful network packet analyzer for troubleshooting and analysis.

**Use Cases:**
- Network traffic analysis
- Protocol inspection

**Platform:** Windows, Linux, macOS

### 2.2 Nmap
**Description:** 
 A network scanning and discovery tool.

**Use Cases:**
- Host discovery
- Port scanning

**Platform:** Cross-platform

### 2.3 Metasploit
**Description:** 
 A penetration testing framework for developing and executing exploits.

**Use Cases:**
- Exploitation
- Vulnerability testing

**Platform:** Cross-platform

### 2.4 Burp Suite
**Description:** 
 A web application security testing tool with proxy and scanner capabilities.

**Use Cases:**
- Web application testing
- Manual and automated scanning

**Platform:** Cross-platform

### 2.5 OWASP ZAP
**Description:** 
 An open-source web application vulnerability scanner.

**Use Cases:**
- Scanning for web app vulnerabilities
- Security testing automation

**Platform:** Cross-platform

### 2.6 Nessus
**Description:** 
 A comprehensive vulnerability scanner.

**Use Cases:**
- Network vulnerability scanning
- Compliance auditing

**Platform:** Windows, Linux, macOS

### 2.7 Nikto
**Description:** 
 A web server scanner for detecting outdated software and misconfigurations.

**Use Cases:**
- Web vulnerability detection
- Server misconfiguration checks

**Platform:** Cross-platform

### 2.8 John the Ripper
**Description:** 
 A password-cracking tool for security testing.

**Use Cases:**
- Password auditing
- Cracking password hashes

**Platform:** Cross-platform

### 2.9 Hashcat
**Description:** 
 A high-performance password recovery tool using GPU acceleration.

**Use Cases:**
- Cracking password hashes
- Penetration testing

**Platform:** Cross-platform

### 2.10 sqlmap
**Description:** 
 An automated tool for detecting and exploiting SQL injection.

**Use Cases:**
- SQL injection detection
- Database takeover

**Platform:** Cross-platform

### 2.11 Suricata
**Description:** 
 A high-performance network IDS/IPS and network security monitoring engine.

**Use Cases:**
- Intrusion detection
- Network traffic analysis

**Platform:** Linux, Windows

### 2.12 Snort
**Description:** 
 A lightweight IDS/IPS system for real-time traffic analysis.

**Use Cases:**
- Packet analysis
- Attack signature detection

**Platform:** Linux, Windows

### 2.13 Autopsy
**Description:** 
 A digital forensic tool with a GUI built on The Sleuth Kit.

**Use Cases:**
- File system forensics
- Disk imaging analysis

**Platform:** Windows, Linux

### 2.14 Splunk
**Description:** 
 A data analytics platform often used for SIEM and log correlation.

**Use Cases:**
- Threat detection
- Log analysis

**Platform:** Web-based, CLI

### 2.15 ELK Stack
**Description:** 
 A log aggregation and analytics stack using Elasticsearch, Logstash, and Kibana.

**Use Cases:**
- Security log analysis
- Centralized monitoring

**Platform:** Linux, Docker-based

### 2.16 Lynis
**Description:** 
 An open-source security auditing tool for Unix-based systems, used to perform in-depth system scans to assess system security and compliance.

**Use Cases:**
- Security auditing and hardening
- Vulnerability detection
- Compliance testing (e.g., CIS, PCI-DSS)
- System benchmarking

**Platform:** Unix-based systems (Linux, macOS, BSD)


-----------------------------------------------------------------------------------------------------------------------------------------------------
## 3 Frameworks

### 3.1 NIST Cybersecurity Framework (CSF)
**Description:** 
 A framework that provides guidelines for managing and reducing cybersecurity risk.

**Source:** 
 NIST

**Compliance Areas:**
- Risk Management 
- Governance 
- Incident Response 
- Asset Protection 

### 3.2 NIST 800-53
**Description:** 
 A catalog of security and privacy controls for federal information systems.

**Source:** 
 NIST

**Compliance Areas:**
- Access Control 
- Audit and Accountability 
- System Integrity 
- Compliance 

### 3.3 NIST 800-61
**Description:** 
 A guide to computer security incident handling.

**Source:** 
 NIST

**Compliance Areas:**
- Incident Response 
- Threat Detection 
- Security Operations 

### 3.4 ISO/IEC 27001
**Description:** 
 A global standard for information security management systems (ISMS).

**Source:** 
 ISO/IEC

**Compliance Areas:**
- Information Security 
- Governance 
- Compliance 
- Risk Assessment 

### 3.5 ISO/IEC 27002
**Description:** 
 A code of practice for information security controls.

**Source:** 
 ISO/IEC

**Compliance Areas:**
- Access Control 
- Asset Management 
- Security Policies 

### 3.6 MITRE ATT&CK
**Description:** 
 A knowledge base of adversary tactics and techniques based on real-world observations.

**Source:** 
 MITRE

**Compliance Areas:**
- Threat Intelligence 
- Threat Detection 
- SOC Operations 

### 3.7 CIS Controls
**Description:** 
 A set of best practices to help organizations improve their cybersecurity posture.

**Source:** 
 Center for Internet Security (CIS)

**Compliance Areas:**
- Endpoint Security 
- Access Management 
- Data Protection 
- System Hardening 

### 3.8 OWASP Top 10
**Description:** 
 A standard awareness document for the most critical web application security risks.

**Source:** 
 OWASP

**Compliance Areas:**
- Application Security 
- Secure Coding 
- Web Security 

### 3.9 GDPR
**Description:** 
 A regulation for data protection and privacy in the EU.

**Source:** 
 European Union

**Compliance Areas:**
- Privacy 
- Data Protection 
- Compliance 

### 3.10 SOC 2
**Description:** 
 A reporting framework focusing on controls relevant to security, availability, processing integrity, confidentiality, and privacy.

**Source:** 
 AICPA

**Compliance Areas:**
- Cloud Security 
- Data Protection 
- Vendor Management 

### 3.11 COBIT
**Description:** 
 A framework for governance and management of enterprise IT.

**Source:** 
 ISACA

**Compliance Areas:**
- IT Governance 
- Risk Management 
- Compliance 

### 3.12 FAIR (Factor Analysis of Information Risk)
**Description:** 
 A model for understanding, analyzing, and quantifying information risk.

**Source:** 
 FAIR Institute

**Compliance Areas:**
- Risk Quantification 
- Risk Management 
- Strategic Decision Making 


-----------------------------------------------------------------------------------------------------------------------------------------------------
