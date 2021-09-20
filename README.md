# PowerStrike  

PowerStrike is a PowerShell based framework that assists a SOC Analyst to query or contain multiple hosts simultaneously via the CrowdStrike OAuth2 API.  
It uses an open source PowerShell module PSFalcon with custom PowerShell to allow direct interaction with CrowdStrike.  

### Requirements:  

-	Requires PSFalcon PowerShell module - "Install-Module -Name PSFalcon -Scope CurrentUser"  
-	Requires CrowdStrike OAuth2 API credentials with appropriate access scopes.  
-	Requires CrowdStrike Key-Based API credentials with access to Threat Graph API.  

### Current Capabilities:  
-	Can be configured to communicate to the API via a proxy  
-	Obtain or revoke an OAuth2 token.  
-	Configure output to CSV or TXT file.  
-	Input hosts for queries via manual input or text file or both.  
	o	Host input accepts Hostname, Agent ID, Cloud Instance ID or External IP address.  
-	Obtain basic host information about multiple hosts.  
-	Query and return any detections for multiple hosts.  
-	Can contain and uncontain multiple hosts.  
-	Can launch Real Time Responder and input queries on multiple hosts including:  
	o	Normal RTR commands (netstat, ps, mount, ls etc.)  
	o	Any on the fly custom powershell  
	o	Launch any valid script via runscript command  
	o	Launch KAPE IR artefact collection  
	o	Download file from a single host at a time  
	o	Supports queuing commands for offline hosts  
-	Threat Graph API integration  
	o	Search for hashes and domains ofrom historical CrowdStrike data  
	o	Include hosts from IOC matches into scope for further queries  

### Planned future capabilities:  
-	Real Time response configuration  
	o	Create, Update and Delete custom Real Time Response Scripts  
	o	Upload and Delete Real Time Response files  
-	Create, Update and Delete custom IOAs/IOCs  
-	Host Group and Policy Management
	o	Create, Update and Delete Host Groups
	o	Create, Update and Delete Policies  
	o	Apply and Remove Policies from Host Groups  






