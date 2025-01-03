### WaZuh Security Insights and Enhancements

<!-- ![WaZuh Logo](./images/wazuh-logo-v2.png) -->

<div align="center"> <img src="./images/wazuh-logo-v2.png" alt="WaZuh Logo"> </div>

<br />

Welcome to **WaZuh Security Insights and Enhancements**,

This project serves as a comprehensive resource for anyone interested in leveraging WaZuh for **X**tended **D**etection and **R**esponse (**XDR**) and **S**ecurity **I**nformation and **E**vent **M**anagement (**SIEM**). Here, you'll find a collection of valuable enhancements, custom dashboards, and personal learnings.

1. **Comprehensive Overview:** Instantly access a complete overview of all security events detected by WaZuh, providing a clear and concise snapshot of the current security landscape.
2. **Insightful Dashboards:** Utilize these dashboards to thoroughly review and analyze security insights identified by WaZuh, enabling a deeper understanding of potential threats and vulnerabilities.
3. **Periodic Reviews:** Leverage these dashboards for regular reviews of security events, helping to systematically narrow down findings and focus on critical issues.
4. **Advanced Filtering:** Each field within the dashboard offers powerful filtering capabilities, allowing for detailed insights and the ability to drill down into specific events for more granular analysis.

<br />

#### What's Inside:

1. **[Custom Dashboards:](#custom-dashboards)** Dive into Custom dashboards that visualize critical security metrics and insights.

2. **[Enhancements:](#enhancements)** Explore various improvements and tweaks to optimize WaZuh's functionality.

3. **[Learnings:](#learnings)** Benefit from my experiences and key takeaways while working with WaZuh XDR and SIEM.

4. **[Resources:](#resources)** Access documentation and guides to help you get started and make the most out of WaZuh.

<br />

## Custom Dashboards


**1. Overview of the Dashboards:  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [[Full View &#8599;](./Dashboard.Readme.md)]**
<br/>

#### CISO Dashboard | Security Anomaly Detection

![CISO Dashboard | Security Anomaly Detection](./Dashboard-Snaps/CISO-Dashboard_Security-Anomaly-Detection-001-Overview.png)

#### CISO Dashboard | AWS Security

![CISO Dashboard | AWS Security](./Dashboard-Snaps/CISO-Dashboard_AWS-Security-001-Overview.png)

#### CISO Dashboard | System Anomaly Detection

![CISO Dashboard | System Anomaly Detection](./Dashboard-Snaps/CISO-Dashboard_System-Anomaly-Detection-001-Overview.png)


<br />
 
| Dashboard      | Exports       | 
|:----------|:------------:|
| CISO Dashboard \| Security Anomaly Detection | [Download](./Dashboard-Exports/CISO_Dashboard__Security_Anomaly_Detection.ndjson)  |
| CISO Dashboard \| AWS Security | [Download](./Dashboard-Exports/CISO_Dashboard__AWS_Security.ndjson)  |
| CISO Dashboard \| System Anomaly Detection | [Download](./Dashboard-Exports/CISO_Dashboard__System_Anomaly_Detection.ndjson)  |



_Note: Above Dashboards are in ndjson format, download the file and then follow below steps_

<br />

**2. How to Integrate:**

1. Go to WaZuh ➔ Stack Management ➔ Saved Objects ➔ Import

    - CISO Dashboard | Security Anomaly Detection <a href="./Dashboard-Exports/CISO_Dashboard__Security_Anomaly_Detection.ndjson" target="_blank">Download ➔</a>
    - CISO Dashboard | System Anomaly Detection <a href="./Dashboard-Exports/CISO_Dashboard__System_Anomaly_Detection.ndjson" target="_blank">Download ➔</a>
    - CISO Dashboard | AWS Security <a href="./Dashboard-Exports/CISO_Dashboard__AWS_Security.ndjson" target="_blank">Download ➔</a>    

## Enhancements:

**A) WaZuh Extenal API Integrations <a href="https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html" target="_blank">&#8599;</a>**



**1. Monitoring Email Overview  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  [[Full View &#8599;](./Alerts.Readme.md)]**




##### FIM Email Alert
![FIM Email Alert](./Integration-Scripts/alerts/Integration-CustomEmail-Alert-FIM-Events.png)

<br />

##### Guardduty Email Alert
![FIM Email Alert](./Integration-Scripts/alerts/Integration-CustomEmail-Alert-Guardduty-Events.png)



**2. How to Integrate:**


**Step 1: Download the Custom Integration Script**

| Resources      | Link       |
|:----------|:------------:|
| Custom Alerts Email PY | [Go to Download](./Integration-Scripts/custom-email-alerts.py)  |

**Step 2: Setup the Script File**

Add this Script inside: `/var/ossec/integrations/`

Set Permission
```sh
chown root:wazuh /var/ossec/integrations/custom-alerts-email.py
chmod 750 /var/ossec/integrations/custom-alerts-email.py
```

**Step 3: Integration in WaZuh**

Use the Below XML Section inside WaZuh Manager ossec.conf

```xml
<!-- For GuardDuty: Custom GuardDuty Formatter -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>aws_guardduty</group>
    <api_key>Guardduty</api_key>
    <alert_format>json</alert_format>
</integration>

<!-- For FIM: Custom FIM Formatter -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>syscheck</group>
    <api_key>FIM</api_key>
    <alert_format>json</alert_format>
</integration>

<!-- For SG: Custom SecurityGroups Formatter -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>aws_cloudtrail_securitygroups</group> <!-- A Custom Group in rules need to be created which has all SG related Events -->
    <api_key>SecurityGroups</api_key>
    <alert_format>json</alert_format>
</integration>

<!-- For Any: Custom for Any - Set blank for api_key -->
<integration>
    <name>custom-alerts-email.py</name>
    <hook_url>emailrecipient@example.com</hook_url>
    <group>ossec</group>
    <api_key></api_key>
    <alert_format>json</alert_format>
</integration>
```

<br />

## Learnings:

_Note: To be added soon, work in progress_

![To be Added soon](./images/ToBeAddedSoon.png)

## Resources:

A Quick overview of WaZuh Components

![WaZuh Arch](./images/wazuh-arch.png)

<br/>

| Resources      | Link       |
|:----------|:------------:|
| WaZuh Docs | [Go to Link](https://documentation.wazuh.com/current/getting-started/index.html)  |
| WaZuh Docker Installation | [Go to Link](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)  |
| AWS XDR Integrations | [Go to Link](https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/index.html)  |
| Proof of Concepts | [Go to Link](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html)  |





