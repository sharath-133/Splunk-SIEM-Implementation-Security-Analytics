# Splunk SIEM Implementation & Security Analytics

## Objective

The objective of this project is to implement and utilize Splunk for security information and event management (SIEM) to enhance threat detection, investigation, and response capabilities. By managing log ingestion, performing data analysis, and developing interactive dashboards, this project aims to improve the organization's overall security posture through effective monitoring and incident response.

### Skills Learned
- Data Parsing and Enrichment: Managed the ingestion and parsing of various log types using advanced regular expressions for enhanced visibility.

- Threat Detection: Conducted comprehensive log analysis to identify suspicious activities and potential threats.

- Incident Investigation: Utilized SPL and external tools (like VirusTotal) for in-depth analysis of malicious URLs and IPs.

- Dashboard Creation: Developed interactive dashboards for real-time monitoring of security metrics, facilitating proactive threat hunting.

- Automation and Alerting: Created complex SPL queries to automate alerts and streamline the incident response process.

### Tools Used
- Splunk: The primary platform for SIEM implementation and security analytics.
- SPL (Search Processing Language): Used for querying and analyzing log data.
- Advanced Regular Expressions: For parsing and enriching log data from various sources.


## Steps to Upload Sample Log Files (DNS, FTP, SMTP, SSH) to Splunk SIEM

1. **Prepare Sample Log Files**
    - Obtain sample log files in a suitable format (e.g., text files).
    - Ensure the log files contain relevant events for each protocol:
        - **DNS**: Source IP, destination IP, domain name, query type, response code.
        - **FTP**: Source IP, destination IP, username, action (e.g., login, upload, download), timestamp.
        - **SMTP**: Source IP, destination IP, sender email, recipient email, subject, timestamp.
        - **SSH**: Source IP, destination IP, username, action (e.g., login, failed attempts), timestamp.
    - Save the sample log files in a directory accessible by the Splunk instance.
2. **Upload Log Files to Splunk**
    - Log in to the Splunk web interface.
    - Navigate to **Settings > Add Data**.
    - Select **Upload** as the data input method.
3. **Choose File**
    - Click on **Select File** and choose the sample log file you prepared earlier.
4. **Set Source Type**
    - In the **Set Source Type** section, specify the source type for the uploaded log file.
    - Choose the appropriate source type for each log type (e.g., `dns`, `ftp`, `smtp`, `ssh` or custom source types if applicable).
5. **Review Settings**
    - Review other settings such as index, host, and sourcetype.
    - Ensure the settings are configured correctly to match the sample log file.
6. **Click Upload**
    - Once all settings are configured, click on the **Review** button.
    - Review the settings one final time to ensure accuracy.
    - Click **Submit** to upload the sample log file to Splunk.
7. **Verify Upload**
    - After uploading, navigate to the search bar in the Splunk interface.
    - Run a search query to verify that the uploaded events are visible.
        - For DNS: `index=<your_dns_index> sourcetype=<your_dns_sourcetype>`
        - For FTP: `index=<your_ftp_index> sourcetype=<your_ftp_sourcetype>`
        - For SMTP: `index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>`
        - For SSH: `index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>`

---

## Steps to Analyze Log Files (DNS, FTP, SMTP, SSH) in Splunk SIEM

1. **Search for Events**
    - Open the Splunk interface and navigate to the search bar.
    - Enter the following search query to retrieve events for each log type:
        - For DNS: `index=* sourcetype=dns`
        - For FTP: `index=* sourcetype=ftp`
        - For SMTP: `index=* sourcetype=smtp`
        - For SSH: `index=* sourcetype=ssh`

          
2. **Extract Relevant Fields**
    - Identify key fields for each log type:
        - **DNS**: Source IP, destination IP, domain name, query type, response code.
        - **FTP**: Source IP, destination IP, username, action, timestamp.
        - **SMTP**: Source IP, destination IP, sender email, recipient email, subject, timestamp.
        - **SSH**: Source IP, destination IP, username, action, timestamp.
    - Example extraction command for DNS logs:
        
        ```
        splCopy code
        index=* sourcetype=dns | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
        
        ```
        
3. **Identify Anomalies**
    - Look for unusual patterns or anomalies in activity.
    - Example query to identify spikes in DNS activity:
        
        ```
        splCopy code
        index=* sourcetype=dns | stats count by fqdn
        
        ```
        
4. **Find the Top Sources**
    - Use the `top` command to count occurrences of each event type:
        - For DNS: `index=* sourcetype=dns | top fqdn, src_ip`
        - For FTP: `index=* sourcetype=ftp | top username, action`
        - For SMTP: `index=* sourcetype=smtp | top sender_email, recipient_email`
        - For SSH: `index=* sourcetype=ssh | top username, action`

          
5. **Investigate Suspicious Activities**
    - Search for domains or actions associated with known malicious activity.
    - Utilize threat intelligence feeds or reputation databases for analysis.
    - Example search for known malicious domains in DNS logs:
        
        ```
        splCopy code
        index=* sourcetype=dns fqdn="maliciousdomain.com"
        
        ```
