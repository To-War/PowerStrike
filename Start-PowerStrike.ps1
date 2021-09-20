<#
.SYNOPSIS
PowerStrike is a CLI framework for interacting with the CrowdStrike OAuth2 API using the PowerShell module PSFalcon.

.DESCRIPTION
PowerStrike allows an authenticated user to issue commands to one or more endpoints with CrowdStrike installed. 

.NOTES
Date: 26 June 2020
Updated: 14 July 2021
Status: Development
Contact Point: To-War

.PREREQUISITE
PSFalcon v2.1.3
OAuth2 Token with the following API Scopes assigned:
-DETECTIONS
-HOSTS
-REAL TIME RESPONSE (ADMIN)
CrowdStrike Key-Based APIs (deprecated) credentials - For Threat Graph API

.EXAMPLE
./Start-PowerStrike.ps1
#>

#Set script-wide Variables. 
$script:token = $null #Placeholder for OAuth2 token
$script:OutType = "Export-CSV" #Output type
$script:OutPath = $env:USERPROFILE #Output path for all exported data
$script:OutFile = $null #Output filename for hostinfo and detections
$script:HostIDList = @() #Array for HostIDList which is the host AID
$script:HostList = @() #Array for a list of Hosts
$script:HostTable = @{} #Hashtable for storing AID:Hostname key pair
$script:BatchID = $null #Variable for RTR batch ID. Used for sending RTR commands to hosts
$script:BatchTime = $null #Variable to store time BatchID obtained. Used to check if BatchID still valid
$script:RTRCommandList = @("cat", "cd", "clear", "cp", "encrypt", "env", "eventlog", "filehash", "getsid", "history", "ipconfig", "kill", "ls", "map", "memdump", "mkdir", "mount", "mv", "netstat", "ps", "put", "reg delete", "reg load", "reg unload", "reg set", "reg query", "restart", "rm", "run", "runscript", "shutdown", "unmap", "xmemdump", "zip", "csrutil", "ifconfig", "umount", "update history", "update install", "update list", "users") #All valid RTR commands via OAuth2, NB 'get' is done separately.
$script:hostname = $null #Variable to pass hostname between functions for more targeted RTR
$script:aid = $null #Variable to pass computername between functions for more targeted RTR
$script:RTRScriptId = @() #Array to hold a list RTR script IDs
$script:customInfo = @() #Array for storing script information
$script:RTRCommand = $null #Variable for storing RTR command
$script:argument = $null #Variable for storing extra RTR command
$script:selectedCustom = $null #Variable for storing selected custom script name
$script:results = @() #Array to hold query results
$script:filter = $null #Variable to hold host filter
$script:sessionID = $null #Variable to hold session IDs for get file requests
$script:dest = $null #Variable for storing destination of get file requests
$script:ThreatTokenSet = 0 #Token to indicate credentials have been added
$script:clientid = $null #ClientID for Threat Graph
$script:secret = $null #Secret for threatgraph, stored as securestring
$script:IOC = $null #IOC to be idetified
$script:IOCTable = @{} #Hashtable of IOCs. Name = IOC, Value = Type
$script:IOCResponse = @() #Array to hold response data for IOC data

#Falconart generated using "standard" font at: https://patorjk.com/software/taag/
$falconart = @"
 ____                        ____  _        _ _        ____  
|  _ \ _____      _____ _ __/ ___|| |_ _ __(_) | _____|___ \ 
| |_) / _ \ \ /\ / / _ \ '__\___ \| __| '__| | |/ / _ \ __) 
|  __/ (_) \ V  V /  __/ |   ___) | |_| |  | |   <  __// __/ 
|_|   \___/ \_/\_/ \___|_|  |____/ \__|_|  |_|_|\_\___|_____
                                                                                                                          
"@ 

#Main menu of PowerStrike
Function Start-MainMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** PowerStrike Configuration ***"-ForegroundColor Red
    Write-Host "0: Set Proxy Credentials"
    Write-Host "1: Get OAuth2 Token"
    Write-Host
    Write-Host "*** Output Configuration ***"-ForegroundColor Red
    Write-Host "2: Configure Output and Reporting"
    Write-Host
    Write-Host "*** Hosts ***"-ForegroundColor Red
    Write-Host "3: Set/Remove Hosts in Scope"
    Write-Host "4: List Hosts in Scope"
    Write-Host
    Write-Host "*** Host Info & Detections ***"-ForegroundColor Red
    Write-Host "5: Host Information & List Detections"
    Write-Host
    Write-Host "*** Containment ***"-ForegroundColor Red
    Write-Host "6: Contain or Uncontain Hosts"
    Write-Host
    Write-Host "*** Real Time Responder ***"-ForegroundColor Red
    Write-Host "7: Launch Real Time Response"
    Write-Host
    Write-Host "*** PowerStrike: Queued Offline ***"-ForegroundColor Red
    Write-Host "8: Download Queued Offline report"
    Write-Host "9: Download File from Offline Queue"
    Write-Host
    Write-Host "*** Threat Graph: IOC search ***"-ForegroundColor Red
    Write-Host "10: Set API Credentials"
    Write-Host "11: Clear API Credentials"
    Write-Host "12: Run IOC search"
    Write-Host
    Write-Host "*** Revoke / Exit ***"-ForegroundColor Red
    Write-Host "13: Revoke OAuth2 token"
    Write-Host "Q: Quit PowerStrike"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main]"
        switch ($selection)
        {
            '0' {               
                Set-Proxy
                Start-MainMenu
                }
            '1' {
                Get-Token
                Start-MainMenu
                }
            '2' {
                Start-OutputAndReportingMenu
                }
            '3' {
                Start-WorkstationScopeMenu
                }
            '4' {
                Show-Workstations
                Start-MainMenu
                }
            '5' {
                if ($script:HostList.count -eq 0){
                    Write-Host "[!] No host in scope." -ForegroundColor Red
                    Pause
                    Start-MainMenu
                }
                Start-InformationAndDetectionsMenu
                }
            '6' {
                if ($script:HostList.count -eq 0){
                    Write-Host "[!] No host in scope." -ForegroundColor Red
                    Pause
                    Start-MainMenu
                }
                Start-ContainmentMenu
                }
            '7' {
                if ($script:HostList.count -eq 0){
                    Write-Host "[!] No host in scope." -ForegroundColor Red
                    Pause
                    Start-MainMenu
                }
                #Obtain list of custom scripts
                Get-ScriptId
                Start-RealTimeResponseMenu
                }
            '8' {
                Get-FalconQueuedReport
                Start-MainMenu
                }
            '9' {
                Get-FalconQueuedFile
                Start-MainMenu
                }
            '10'{
                Set-ThreatCreds
                Start-MainMenu
                }
            '11'{
                Clear-ThreatCreds
                Start-MainMenu
                }
            '12'{
                if ($script:ThreatTokenSet -eq 0) {
                    Write-Host "[!] No credentials set." -ForegroundColor Red
                    Pause
                    Start-MainMenu
                }
                Start-IOCSearchMenu
                }
            '13'{
                Revoke-Token
                Start-MainMenu
                }
            'q' {
                Write-Host "[!] Exiting" -ForegroundColor Red
                Revoke-Token
                Remove-Variable -Name Falcon -Scope Global -ErrorAction SilentlyContinue
                Exit
                }
        }
    }
    until ($selection -eq 'q')
}

#Output and Reporting sub-menu
function Start-OutputAndReportingMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** Master Output Configuration ***" -ForegroundColor Red
    Write-Host "1: Set Master Output Path"
    Write-Host "2: Set Output Filename Prefix"
    Write-Host
    Write-Host "*** Host Info & Detection Output Configuration ***" -ForegroundColor Red
    Write-Host "3: Set Output Format: Custom CSV"
    Write-Host "x: Set Output Format: Falcon Report"
    Write-Host "4: Set Output Format: TXT"
    Write-Host
    Write-Host "*** Show & Clear Output Configuration ***" -ForegroundColor Red
    Write-Host "5: Display Output Format, Path and Filename Prefix"
    Write-Host "6: Restore default settings"
    Write-Host
    Write-Host "*** Back to Main ***" -ForegroundColor Red
    Write-Host "Q: Return to Main Menu"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main > Get Detections > Set Output Configuration]"
        switch ($selection)
        {
            '1' {
                Set-MasterPath
                Start-OutputAndReportingMenu
                }
            '2' {
                $script:OutFile = Read-Host "Set output filename prefix (e.g. 'output' or 'INC1234567890)" 
                Write-Host "[+] Output file set to $script:OutFile"- -ForegroundColor Yellow
                Pause
                Start-OutputAndReportingMenu
                }
            '3' {
                $script:OutType = "Export-CSV"
                Write-Host "[+] Output set to Custom CSV file" -ForegroundColor Yellow
                Pause
                Start-OutputAndReportingMenu
                }
            'x' {
                $script:OutType = "Export-Falcon"
                Write-Host "[+] Output set to Falcon Report file" -ForegroundColor Yellow
                Pause
                Start-OutputAndReportingMenu
                }
            '4' {
                $script:OutType = "Export-TXT"
                Write-Host "[+] Output set to text file" -ForegroundColor Yellow
                Pause
                Start-OutputAndReportingMenu
                }
            '5' {
                Write-Host "[+] Output Format: $script:OutType" -ForegroundColor Yellow
                Write-Host "[+] Output Path: $script:OutPath" -ForegroundColor Yellow
                Write-Host "[+] Output Prefix: $script:OutFile" -ForegroundColor Yellow
                Pause
                Start-OutputAndReportingMenu
                }
            '6' {
                $script:OutPath = $env:USERPROFILE #Set OutPath to default
                $script:OutFile = $null
                $script:OutType = "Export-CSV"
                Write-Host "[+] Output type, path and filename defaults restored." -ForegroundColor Yellow
                Pause
                Start-OutputAndReportingMenu
                }
            'q' {
                Start-MainMenu
                }
        }
    }
    until ($selection -eq 'q')
}

#Workstations sub-menu
Function Start-WorkstationScopeMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** PowerStrike: Set Hosts ***" -ForegroundColor Red
    Write-Host "1: Manual Host Input"
    Write-Host "2: Import text file of Hosts"
    Write-Host "3: Search for Hosts by External IP"
    Write-Host "x: Get all host AIDs in CID"
    Write-Host
    Write-Host "*** PowerStrike: Review Hosts ***" -ForegroundColor Red
    Write-Host "4: Clear Host & AID List"
    Write-Host "5: List Hosts in Scope"
    Write-Host
    Write-Host "*** Back to Main ***" -ForegroundColor Red
    Write-Host "Q: Return to Main Menu"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main > Set Hosts]"
        switch ($selection)
        {
            '1' {               
                Set-HostManual
                Start-WorkstationScopeMenu
                }
            '2' {
                Set-HostFile
                Start-WorkstationScopeMenu
                }
            '3' {
                Run-IPSearch
                Start-WorkstationScopeMenu
                }
            '4' {
                #Clears HostList, HostIDList, HostTable and BatchID
                $script:HostList = @()
                $script:HostIDList = @()
                $script:HostTable = @{}
                $script:BatchID = $null
                Write-Host "[+] Hostname and AID lists have been cleared" -ForegroundColor Yellow
                Pause
                Start-WorkstationScopeMenu
                }
            '5' {
                Show-Workstations
                Start-WorkstationScopeMenu
                }
            'x' {
                Get-AllHosts
                Start-WorkstationScopeMenu
                }
            'q' {
                Start-MainMenu
                }
        }
    }
    until ($selection -eq 'q')
}

#Get-Detection Sub-Menu
Function Start-InformationAndDetectionsMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** PowerStrike: Get Information & Detections ***"-ForegroundColor Red
    Write-Host "1: Search for Host Information"
    Write-Host "2: Search for Host Detections"
    Write-Host
    Write-Host "*** PowerStrike: List Hosts ***" -ForegroundColor Red
    Write-Host "3: List Hosts in Scope"
    Write-Host
    Write-Host "*** Back to Main ***"-ForegroundColor Red
    Write-Host "Q: Return to Main Menu"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main > Get Information & Detections]"
        switch ($selection)
        {
            '1' {
                if ($script:HostList.count -eq 0) 
                {
                    Write-Host "[!] No workstations have been set. Returning to Main Menu" -ForegroundColor Red
                    Pause
                    Start-MainMenu
                }
                Get-HostInfo
                Start-InformationAndDetectionsMenu
                }
            '2' {
                if ($script:HostList.count -eq 0) 
                {
                    Write-Host "[!] No workstations have been set. Returning to Main Menu" -ForegroundColor Red
                    Pause
                    Start-MainMenu
                }
                Get-Detection
                Start-InformationAndDetectionsMenu
                }
            '3' {
                Show-Workstations
                Start-InformationAndDetectionsMenu
                }
            'q' {
                Start-MainMenu
                }
        }
    }
    until ($selection -eq 'q')
}

#Containment sub-menu
Function Start-ContainmentMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** PowerStrike: Hosts ***" -ForegroundColor Red
    Write-Host "0: List Hosts in Scope"
    Write-Host "1: Remove Host from Scope"
    Write-Host
    Write-Host "*** PowerStrike: Start Containment ***"-ForegroundColor Red
    Write-Host "2: Start Containment"
    Write-Host "3: Stop Containment"
    Write-Host
    Write-Host "*** Back to Main ***"-ForegroundColor Red
    Write-Host "Q: Return to Main Menu"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main > Containment]"
        switch ($selection)
        {
            '0' {
                Show-Workstations
                Start-ContainmentMenu
                }
            '1' {
                Remove-HostID
                Start-ContainmentMenu
                }        
            '2' {
                Start-Containment
                }
            
            '3' {
                Stop-Containment
                }
            'q' {
                Start-MainMenu
                }

        }
    }
    until ($selection -eq 'q')
}

#RTR top level Sub-Menu
function Start-RealTimeResponseMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** PowerStrike: RTR Configuration ***"-ForegroundColor Red
    Write-Host "0: List Hosts in Scope"
    Write-Host "1: Get BatchID"
    Write-Host "2: Remove Host from scope"
    Write-Host
    Write-Host "*** PowerStrike: RTR Commands ***"-ForegroundColor Red
    Write-Host "3: Run RTR Commands"
    Write-Host "4: Download file from host"
    Write-Host "x: Run Custom Powershell"
    Write-Host
    Write-Host "*** PowerStrike: RTR Custom Scripts ***"-ForegroundColor Red
    Write-Host "5: Get Custom Script Information"
    Write-Host "6: Run Custom Script - Batch"
    Write-Host "7: Run Custom Script - Bulk"
    Write-Host
    Write-Host "*** PowerStrike: RTR KAPE Collection ***"-ForegroundColor Red
    Write-Host "8: Start KAPE Collection"
    Write-Host "9: Check KAPE completion"
    Write-Host
    Write-Host "*** Back to Main ***" -ForegroundColor Red
    Write-Host "Q: Return to Main Menu"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main > Real Time Response]"
        switch ($selection)
        {
            '0' {
                Show-Workstations
                Start-RealTimeResponseMenu
                }
            '1' {
                Get-BatchID
                Pause
                Start-RealTimeResponseMenu
                }
            '2' {
                Remove-HostID
                Start-RealTimeResponseMenu
                }
            '3' {
                Check-BatchID
                Set-RealTimeResponseCommands
                }
            '4' {
                Get-FilefromCloud
                Start-RealTimeResponseMenu
                }
            '5' {
                Get-ScriptInfo
                Start-RealTimeResponseMenu
                }
            '6' {
                Check-BatchID
                Run-CustomScripts
                Start-RealTimeResponseMenu
                }
            '7' {
                Run-ScriptBulk
                Start-RealTimeResponseMenu
                }
            '8' {
                Check-BatchID
                Start-KAPECollection
                }
            '9' {
                Get-KAPECollectionStatus
                }
            'x' {
                Check-BatchID
                Send-CustomPowerShell
                }
            'q' {
                $script:BatchID = $null
                Start-MainMenu
                }
        }
    }
    until ($selection -eq 'q')
}

#Threat Graph API Menu. Threat Graph requires legacy API credentials.
function Start-IOCSearchMenu() {
    Clear-Host
    Write-Host $falconart -ForegroundColor Red
    Write-Host
    Write-Host "*** Threat Graph: Set IOCs ***"-ForegroundColor Red
    Write-Host "1: Manual IOC input"
    Write-Host "2: Import text file of IOCs"
    Write-Host
    Write-Host "*** Threat Graph: Review IOCs ***"-ForegroundColor Red
    Write-Host "3: List current IOC scope"
    Write-Host "4: Remove IOC from scope"
    Write-Host "5: Clear IOC scope"
    Write-Host
    Write-Host "*** Threat Graph: Search IOCs ***"-ForegroundColor Red
    Write-Host "6: Run Search"
    Write-Host 
    Write-Host "*** Back to Main ***" -ForegroundColor Red
    Write-Host "Q: Return to Main Menu"
    Write-Host
    do {
        $selection = Read-Host "[PowerStrike > Main > Threat Graph > IOC Search]"
        switch ($selection)
        {
            '1' {
                Set-IOCManual
                }
            '2' {
                Set-IOCFile
                }
            '3' {
                if ($script:IOCTable.count -eq 0) {
                    Write-Host "[!] No IOCs in scope. Please enter IOCs and try again." -ForegroundColor Red
                    Pause
                    Start-IOCSearchMenu
                }
                Show-IOC
                Pause
                Start-IOCSearchMenu
                }
            '4' {
                if ($script:IOCTable.count -eq 0) {
                    Write-Host "[!] No IOCs in scope. Please enter IOCs and try again." -ForegroundColor Red
                    Pause
                    Start-IOCSearchMenu
                }
                Remove-IOC
                }
            '5' {
                Clear-IOC
                }
            '6' {
                if ($script:IOCTable.count -eq 0) {
                    Write-Host "[!] No IOCs in scope. Please enter IOCs and try again." -ForegroundColor Red
                    Pause
                    Start-IOCSearchMenu
                }
                Run-IOCSearch
                }
            'q' {
                Start-MainMenu
                }
        }
    }
    until ($selection -eq 'q')
}

#Configure proxy connection
function Set-Proxy() {
    $proxyurl = "http-gw.tcif.telstra.com.au"
    $proxyport = "8080"
    $proxyaddress = $proxyurl+':'+$proxyport
    #Test connection to proxy
    if (Test-Connection -Cn "$proxyurl" -Count 1 -quiet)
    {
        Try 
        {
            #Obtain proxy credentials from user
            $credential = Get-Credential -Message "Please enter proxy credentials"
        } 
        Catch
        {
            Write-Host "[!] Error: Unable to get credentials." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
            Start-MainMenu
        }
        Try 
        {
            #Configure the proxy
            $proxy = New-Object System.Net.WebProxy
            $proxy.Address = [uri]"http://$proxyaddress"
            $proxy.Credentials = $credential
            [System.Net.WebRequest]::DefaultWebProxy = $proxy
            #test proxy conenction
            Invoke-WebRequest -Uri "https://google.com" | Out-Null
            Write-Host "[+] Proxy Authentication successful. Have a nice day :)" -ForegroundColor Yellow
            Pause
            Start-MainMenu
        } 
        Catch
        {
            Write-Host "[!] Error: Proxy authentication failed. Retry" -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
            Start-MainMenu
        }
    } Else {
        Write-Host "[!] Error: Failed to reach proxy. Retry" -ForegroundColor Red
        Pause
    }
}

#Set master output path for all data export
function Set-MasterPath() {
    $script:outpath = ""
    While ($script:outpath.length -eq 0) {
    $script:OutPath = Read-Host "Set Master Output Path (e.g. 'C:\temp\')" 
    }
    Try
    {
        if (Test-Path $script:OutPath -PathType Container) 
        {
            Write-Host "[+] Output path set to $script:OutPath" - -ForegroundColor Yellow
            Pause
        }
        else
        {
            Write-Host "[!] Directory does not exist." -ForegroundColor Red
            $selection = Read-Host "Would you like to create it? y/n"
            switch ($selection) 
            {
                'y' 
                {
                    Write-Host "[+] Attempting to create $script:OutPath" -ForegroundColor Yellow
                    Try {
                        New-Item -Path $script:OutPath -ItemType Directory | Out-Null
                        Write-Host "[+] $script:OutPath created successfully" -ForegroundColor Yellow
                        Pause
                        }
                    Catch {
                        Write-Host "[!] Error: Unable to create $script:OutPath" -ForegroundColor Red
                        Write-Host "[+] Master Out Path reverting to $env:USERPROFILE" -ForegroundColor Yellow
                        $script:OutPath = $env:USERPROFILE
                        $_.Exception.ToString()
                        $error[0] | Format-List -Force
                        Pause
                        }
                }
                'n' 
                {
                    Write-Host "[+] No directory created." -ForegroundColor Yellow
                    Write-Host "[+] Master Out Path reverting to $env:USERPROFILE" -ForegroundColor Yellow
                    $script:OutPath = $env:USERPROFILE
                    Pause
                }   
            }
        }
    }
    Catch
    {
        Write-Host "[!] Error: Failed to set Master Out Path." -ForegroundColor Red
        Write-Host "[+] Master Out Path reverting to $env:USERPROFILE" -ForegroundColor Yellow
        $script:OutPath = $env:USERPROFILE
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Takes input from user and searches for hosts
function Set-HostManual() {
    $input = $Null
    While ($input -ne 'q') 
    { 
        $input = Read-Host "Please type a Hostname, AID or Cloud Instance ID ('q' to stop)"
        if ($input -eq 'q') {
            Start-WorkstationScopeMenu
        }
        elseif ($input.length -eq 0) {
            Write-Host "[!] Input cannot be blank." -ForegroundColor Red
        }
        elseif ($input.length -lt 3) {
            Write-Host "[!] Input too short. Minimum 3 character long." -ForegroundColor Red
        }
        elseif ($script:HostTable.keys -contains $input -Or $script:HostTable.value -contains $input) {
            Write-Host "[!] Duplicate identified. $input is already in scope." -ForegroundColor Red
        }
        elseif ($script:HostTable.keys -notcontains $input -Or $script:HostTable.value -notcontains $input) {
            Write-Host "[+] Looking up $input." -ForegroundColor Yellow
            $script:filter = $input
            Identify-Hosts
        }
    }
    Write-Host "[+] PowerStrike Host scope contains $($script:HostTable.count) hosts" -ForegroundColor Yellow
    Pause
} 

#Takes input from a file and searches for hosts
function Set-HostFile() {
    $HostFile = $Null
    $HostFile = Read-Host "Please enter the full path of the text file (e.g. 'C:\temp\hosts.txt')"
    if (Test-Path $HostFile -PathType Leaf) {
        ForEach ($line in Get-Content $HostFile) 
        {
            if ($script:HostTable.keys -notcontains $line -Or $script:HostTable.value -notcontains $line) 
            {
                #Write-Host "[+] Looking up $line" -ForegroundColor Yellow
                $script:filter = $line
                Identify-Hosts
            }
            elseif ($script:HostTable.name -contains $line -Or $script:HostTable.value -contains $line) {
                Write-Host "[!] Duplicate identified. $line is already in scope." -ForegroundColor Red
            }
        }
        Write-Host "[+] PowerStrike Host scope contains $($script:HostTable.count) hosts" -ForegroundColor Yellow
    }
    else 
    {
        Write-Host "[!] File $HostFile not found. Please check" -ForegroundColor Red
    }
    Pause
}

#function to search hosts on external IP. Takes IPS from a text file and searches in batches of 20.
#PSFalcon API command - Get-FalconHost
function Run-IPSearch() {
    $ip = @()
    $IPFile = Read-Host "Please enter the full path of the text file (e.g. 'C:\temp\ip.txt')"
    if (Test-Path $IPFile -PathType Leaf) {
        Foreach ($line in Get-Content $IPFile) {
            if ($line -Match "(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])") {
                $ip += $line
            } else {
                Write-Host "[!] Invalid entry - $line" -ForegroundColor Red
            }
        }
        Try
        {
            Write-Host "[+] $($ip.count) valid IPs identified." -ForegroundColor Yellow
            Write-Host "[+] Beggining search." -ForegroundColor Yellow
            $HostIDs = for ($i = 0; $i -lt $ip.count; $i += 20) {
                # Retrieve device_id for hostnames in groups of 20
                $filter = ($ip[$i..($i + 19)] | ForEach-Object {
                    if ($_ -ne '') {
                        "external_ip:'$_'"
                    }
                }) -join ','
                #PSFalcon API command - Get-FalconHost 
                Get-FalconHost -filter $filter -ErrorAction SilentlyContinue
                }
            Write-Host "[+] Found $($Hosts.count) hosts. Adding to scope."
            ForEach ($id in $HostIDs)
                {
                    $script:filter = $id
                    Identify-Hosts
                }
        }
        Catch
        {
            Write-Host "[!] Error: Unable to search for Hosts." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    } else {
        Write-Host "[!] Host File not found." -ForegroundColor Red
        Pause
    }
    Pause
}

#Function to take user host input and identify input type
#PSFalcon API command - Get-FalconHost
function Identify-Hosts() {
    Try
    {
        if ($script:filter -match "\w{32}") {
            #If $script:filter is an AID get hostname
            $script:aid = $script:filter
            Write-Host "[+] Identifying host with AID: $script:aid" -ForegroundColor Yellow
            #PSFalcon API command - Get-FalconHost
            $request = Get-FalconHost -Ids $script:aid -ErrorAction SilentlyContinue
            $script:hostname = $request.hostname
            if ($($script:hostname.length) -eq 0) {
                Write-Host "[!] Unable to find hostname with AID:$script:aid." -ForegroundColor Red
            } else {
                Write-Host "[+] Found $script:hostname with AID: $script:aid" -ForegroundColor Yellow
                #Add host to HostTable
                Add-Host
            }
        } elseif ($script:filter -match "i\-\w{17}" -Or $script:filter -match "\w{8}\-\w{4}-\w{4}-\w{4}-\w{12}" -Or $script:filter -match "\d{19}") {
            #If $script:filter is an instance ID
            Write-Host "[+] Identifying Cloud host with instance ID: $script:filter" -ForegroundColor Yellow
            #PSFalcon API command - Get-FalconHost
            $request = Get-FalconHost -Filter "instance_id:'$script:filter'" -Detailed -ErrorAction SilentlyContinue
            if ($request.count -eq 0) {
                Write-Host "[!] Unable to identify $script:filter." -ForegroundColor Red
            } elseif ($request.count -eq 1) {
                Write-Host "[+] Found AID: $request for instance ID: $script:filter" -ForegroundColor Yellow
                #Add host to HostTable
                $script:aid = $($request.device_id)
                $script:hostname = $($request.hostname)
                Add-Host
            } elseif ($request.count -gt 1) {
                Write-Host "[+] Instance ID: $script:filter has $($request.count) AIDs" -ForegroundColor Yellow
                $input = ''
                while ($input -ne 'n' -And $input -ne 'y' -And $input -ne 'all') {
                    $input = Read-Host "Would you like to filter on last seen or add all AIDs? y/n/all (Select 'n' to remove or 'all' to add all AIDs)"
                    switch ($input) {
                        'all' {
                                foreach ($_ in $request) {
                                    #Add host to HostTable
                                    $script:aid = $($_.device_id)
                                    $script:hostname = $($_.hostname)
                                    Add-Host
                                }
                            }
                        'y' {
                                #PSFalcon API command - Get-FalconHost
                                $request = Get-FalconHost -Filter "instance_id:'$script:filter'" -Sort last_seen.desc -Limit 1 -Detailed -ErrorAction SilentlyContinue
                                $script:aid = $($request.device_id)
                                $script:hostname = $($request.hostname)
                                Add-Host
                            }
                        'n' {
                                Write-Host "[+] Skipping. Host will not be added to scope." -ForegroundColor Yellow
                            }
                    }
                }
            }
        } else {
            #If Script:Computer is a hostname get 
            $script:hostname = $script:filter
            Write-Host "[+] Identifying host with Hostname: $script:hostname" -ForegroundColor Yellow
            #PSFalcon API command - Get-FalconHost
            $request = Get-FalconHost -Filter "hostname:'$script:hostname'" -ErrorAction SilentlyContinue
            if ($request.count -eq 0) {
                Write-Host "[!] Unable to identify $script:hostname." -ForegroundColor Red
            } elseif ($request.count -eq 1) {
                Write-Host "[+] Found $script:hostname with AID: $request" -ForegroundColor Yellow
                #Add host to HostTable
                $script:aid = $request
                Add-Host
            } elseif ($request.count -gt 1) {
                Write-Host "[+] Hostname: $script:hostname has $($request.count) AIDs" -ForegroundColor Yellow
                $input = ''
                while ($input -ne 'n' -And $input -ne 'y') {
                    $input = Read-Host "Would you like to add them all? y/n (Select 'n' to add a filter or remove)"
                    switch ($input) {
                        'y' {
                                foreach ($aid in $request) {
                                    #Add host to HostTable
                                    $script:aid = $aid
                                    Add-Host
                                }
                            }
                        'n' {
                                #function filter get-falconhost
                                Filter-Host
                            }
                    }
                }
            }
        }
    }
    Catch 
    {
        Write-Host "[!] Error: Unable to identify user input." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Allows user to filter hosts
#PSFalcon API command - Get-FalconHost
function Filter-Host() {
    $input = ''
    $input = Read-Host "Would you like to filter on public IP address, cloud account, the AID with most recent hartbeat, or remove the host from scope? ip/cloud/last/remove"
    if ($input -eq "ip") {
        Try
        {
            $ip = Read-Host "Enter an IP address (or 'q' to change filters)"
            #Test for valid IP
            if ($ip -eq 'q') {
                Filter-Host
            } elseif ($ip -Match "\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b") {
                Write-Host "[+] Searching for Hostname: $script:hostname with External IP: $ip" -ForegroundColor Yellow
                #PSFalcon API command - Get-FalconHost - filter ip
                $script:aid = Get-FalconHost -Filter "hostname:'$script:hostname'+external_ip:'$ip'" -Sort last_seen.desc -Limit 1 -ErrorAction SilentlyContinue
                if (!$script:aid) {
                    Write-Host "[!] No host found with external IP: $ip" -ForegroundColor Red
                } else {
                    Write-Host "[+] Found AID: $script:aid for $script:hostname - $ip" -ForegroundColor Yellow
                    #add host to scope
                    Add-Host
                }
            } else {
                Write-Host "[!] Invalid input." -ForegroundColor Red
                Filter-Host
            }
        }
        Catch 
        {
            Write-Host "[!] Error: Unable to find host." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    } elseif ($input -eq "cloud") {
        Try
        {
            $account = Read-Host "Enter a cloud account ID (or 'q' to change filters)"
            if ($account -eq 'q') {
                Filter-Host
            } elseif ($account -Match "\w{8}\-\w{4}-\w{4}-\w{4}-\w{12}" -Or $account -Match "\d{12}") {
                Write-Host "[+] Searching for $script:hostname in Account: $account" -ForegroundColor Yellow
                #PSFalcon API command - Get-FalconHost - filter service_provider_account_id
                $script:aid = Get-FalconHost -Filter "hostname:'$script:hostname'+service_provider_account_id:'$account'" -Sort last_seen.desc -Limit 1 -ErrorAction SilentlyContinue
                if (!$script:aid) {
                    Write-Host "[!] No host found with Account ID: $account" -ForegroundColor Red
                } else {
                    Write-Host "[+] Found AID: $script:aid for $script:hostname - $account" -ForegroundColor Yellow
                    #add host to scope
                    Add-Host
                } 
            } else {
                Write-Host "[!] Invalid input." -ForegroundColor Red
            }
            
        }
        Catch 
        {
            Write-Host "[!] Error: Unable to find host." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    } elseif ($input -eq "last") {
        Try
        {
            Write-Host "[+] Searching for last seen with Hostname: $script:hostname" -ForegroundColor Yellow
            #PSFalcon API command - Get-FalconHost - filter last seen
            $script:aid = Get-FalconHost -Filter "hostname:'$script:hostname'" -Sort last_seen.desc -Limit 1 -ErrorAction SilentlyContinue
            Write-Host "[+] Found AID: $script:aid for $script:hostname" -ForegroundColor Yellow
            Add-Host
        }
        Catch 
        {
            Write-Host "[!] Error: Unable to find host." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    } elseif ($input -eq "remove") {
        #do not add host to HostTable, move on to next input
        Write-Host "[+] Skipping. Host will not be added to scope." -ForegroundColor Yellow
    } else {
        #invalid input loop function
        Write-Host "[!] Invalid input." -ForegroundColor Red
        Filter-Host
    }
}

#Adds host to HostList, HostIDList and Hosttable
function Add-Host() {
    Try
    {
        Write-Host "[+] Adding $script:aid - $script:hostname to scope" -ForegroundColor Yellow
        if ($script:HostTable.keys -notcontains $script:aid) {
            $script:HostTable.add($script:aid, $script:hostname)
            $script:HostIDList += $script:aid
            if ($script:HostList -notcontains $script:hostname) {
                $script:HostList += $script:hostname
            }
            $script:filter = ''
            $script:hostname = ''
            $script:aid = ''
        } elseif ($script:HostTable.keys -contains $script:aid) {
            Write-Host "[!] Duplicate AID found. Host will not be added." -ForegroundColor Red
            $script:filter = ''
            $script:hostname = ''
            $script:aid = ''
        }
    }
    Catch 
    {
        Write-Host "[!] Error: Unable to add host." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Prints current contents of HostList
function Show-Workstations() {
    Write-Host
    Write-Host "Current Hosts in scope:"
    foreach ($ID in $script:HostIDList) {
        Write-Host "$ID : $($script:Hosttable[$ID])"
    }
    Write-Host
    Write-Host "[+] Total Hosts: $($script:HostTable.count)" -ForegroundColor Yellow
    Pause
}

#Function get a valid OAuth2 token for queries
#PSFalcon API command - Request-FalconToken
Function Get-Token() {
    Try 
    {
        #PSFalcon API Function - Request-FalconToken
        $script:token = Request-FalconToken -ErrorAction SilentlyContinue
        if ($script:token -eq "The remote server returned an error: (407) Proxy Authentication Required.")
        {
            Write-Host "[!] Unable to get OAuth2 token. Check proxy credentials." -ForegroundColor Red
            Pause
        }
        else 
        {
            if (($script:token.code -eq '400') -or ($script:token.code -eq '403')) 
            {
                Write-Host "[!] There was a 400/403 authentication error. Try Again." -ForegroundColor Red
                Pause
            }
            elseif ($script:token.code -eq 500)
            {
                Write-Host "[!] There was a 500 server error. Try Again." -ForegroundColor Red
                Pause
            }
            else
            {
                Write-Host "[+] OAuth2 token successfully stored" -ForegroundColor Yellow
                Pause
            }   
        }
    }
    Catch 
    {
        Write-Host "[!] Error: Unable to get OAuth2 token. Possible token/password error or CrowdStrike server error." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Function to revoke OAuth2 token
#PSFalcon API command - Revoke-FalconToken
function Revoke-Token() {
    Try
    {
        #PSFalcon API command - Revoke-FalconToken
        Revoke-FalconToken -ErrorAction SilentlyContinue
        Write-Host "[+] OAuth2 Token revoked successfully" -ForegroundColor Yellow
    }
    Catch
    {
        Write-Host "[!] Error: Unable to revoke token." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
    }
    Pause
}

#Function loads all available Host AIDs into HostIDList
#PSFalcon API command - Get-FalconHost -All
Function Get-AllHosts() {
    Write-Host "[!] WARNING: Requesting all hosts in the CID will take time and be rate limited" -ForegroundColor Red
    Write-Host "[!] Type 'understood' to confirm the request, or 'q' to quit" -ForegroundColor Red
    do 
    {
        $selection = Read-Host ">"
        switch ($selection) {
            'understood' 
                {
                $Request = Get-FalconHost -All -Detailed -ErrorAction SilentlyContinue
                foreach($_ in $Request) {
                    $script:aid = $_.device_id
                    $script:hostname = $_.hostname
                    Add-Host
                }
                Write-Host 
                Write-Host "[+] Total Hosts is $($script:HostTable.count)" -ForegroundColor Yellow
                Pause
                }
            'q' {
                Start-WorkstationScopeMenu
                }   
            }
    }
    until ($selection -eq 'q')
}

#Function gets host details for all hosts in HostIDList
#PSFalcon API command - Get-FalconHost -Ids / Export-FalconReport
function Get-HostInfo() {
    #Get-HostID
    foreach ($aid in $script:HostIDList) {
        Try
        {
            #PSFalcon API command - Get-FalconHost -Ids
            $request = Get-FalconHost -Ids $aid -ErrorAction SilentlyContinue
        }
        Catch
        {
            Write-Host "[!] Error: Failed to get host information for $aid" -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
        if (!$request)
        {
            Write-Host "[!] Failed to get host information for $aid" -ForegroundColor Red
        }
        elseif ($request)
        {
            $props = [ordered]@{
                'Workstation' = $($request.hostname)
                'Domain' = $($request.machine_domain)
                'System Type' =  $($request.product_type_desc)
                'AID' =  $($request.device_id)
                'CID' =  $($request.cid)
                'Agent Local Time' =  $($request.agent_local_time)
                'Agent Version' =  $($request.agent_version)
                'System Manufacturer' =  $($request.system_manufacturer)
                'System Product Name' =  $($request.system_product_name)
                'BIOS Manufacturer' =  $($request.bios_manufacturer)
                'BIOS Version' =  $($request.bios_version)
                'External IP' =  $($request.external_ip)
                'Local IP' =  $($request.local_ip)
                'MAC Address' =  $($request.mac_address)
                'Device First Seen' =  $($request.first_seen)
                'Device Last Seen' =  $($request.last_seen)
                'OS Version' =  $($request.os_version)
                'Last Modified Timestamp' =  $($request.modified_timestamp)
                'Status' = $($request.status)
            }
            Write-Host "[+] Found host information for aid $aid" -ForegroundColor Yellow
            $information = New-Object -TypeName PSObject -Property $props
            $information.PSObject.TypeNames.Insert(0,'TCERT.DetectionInfo')
            if ($script:OutType -eq "Export-TXT") {
                Write-Host "[+] Appending information for aid $aid to text file" -ForegroundColor Yellow
                $information | Out-File "$script:OutPath\$script:OutFile-hostinfo.txt" -Append
            } elseif ($script:OutType -eq "Export-Falcon") {
                Try
                {
                    #PSFalcon API command - Export-FalconReport
                    $request | Export-FalconReport -Path "$script:OutPath\$script:OutFile-FalconReport-host.csv" -ErrorAction SilentlyContinue
                }
                Catch
                {
                    Write-Host "[!] Error: Could not write Falcon Report for AID $aid." -ForegroundColor Red
                    $_.Exception.ToString()
                    $error[0] | Format-List -Force
                    Pause
                }
            }
            else {
                Try
                {
                    Write-Host "[+] Appending information for aid $aid to CSV file" -ForegroundColor Yellow
                    $information | Export-CSV "$script:OutPath\$script:OutFile-hostinfo.csv" -Append -NoTypeInformation
                }
                Catch
                {
                    Write-Host "[!] Error: Could not write CSV Report for AID $aid." -ForegroundColor Red
                    $_.Exception.ToString()
                    $error[0] | Format-List -Force
                    Pause
                }
            }
        }
        Write-Host "[+] Finished collecting information for aid $aid" -ForegroundColor Yellow
        Write-Host
    }
    Pause
}

#Get list of detections based on script:HostList
#PSFalcon API command - Get-FalconDetection / Export-FalconReport
Function Get-Detection() {
    foreach ($hostname in $script:HostList) {
        Write-Host "[+] Getting detections for $hostname" -ForegroundColor Yellow
        Try 
            {
            #PSFalcon API command - Get-FalconDetection
            $request = Get-FalconDetection -Filter "device.hostname: '$hostname'" -ErrorAction SilentlyContinue
            if (!$request) 
                {
                Write-Host "[!] No detection ID for $hostname. No recorded detections." -ForegroundColor Red
                }
            } 
        Catch 
            {
            Write-Host "[!] Error: Could not obtain detections for $hostname. Possible connection issue." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
            }
        if ($request -gt 0)             
        {
            foreach($detectid in $request) 
            {
                #PSFalcon API command - Get-FalconDetection
                $detect = Get-FalconDetection -id $detectid -ErrorAction SilentlyContinue
                $props = [ordered]@{
                'Workstation' = $($detect.device.hostname);
                'UserAccount' = $($detect.behaviors.user_name);
                'UserSID' = $($detect.behaviors.user_id);
                'AID' = $($detect.device.device_id); #This is host AID.
                'BIOS' = $($detect.device.bios_manufacturer);
                'System' = $($detect.device.system_product_name);
                'ExternalIP' = $($detect.device.external_ip);
                'MAC' = $($detect.device.mac_address);
                'LastSeen' = $($detect.device.last_seen);
                'OperatingSystem' = $($detect.device.os_version);
                'HostType' = $($detect.device.product_type_desc);
                'Domain' = $($detect.device.machine_domain);
                'DetectStart' = $($detect.first_behavior);
                'DetectEnd' = $($detect.last_behavior);
                'Scenario' = $($detect.behaviors.scenario);
                'Objective' = $($detect.behaviors.objective);
                'Tactic' = $($detect.behaviors.tactic);
                'Technique' = $($detect.behaviors.technique);
                'Action' = $($detect.behaviors.behaviors.pattern_disposition);
                'IOC' = $($detect.behaviors.ioc_type);
                'IOCSource' = $($detect.behaviors.ioc_source);
                'IOCDescription' = $($detect.behaviors.ioc_description);
                'Filename' = $($detect.behaviors.filename);
                'CommandLine' = $($detect.behaviors.cmdline);
                'SHA256' =  $($detect.behaviors.sha256);
                'MD5' =  $($detect.behaviors.md5);
                'ParentProcess' = $($detect.behaviors.parent_details.parent_cmdline);
                'ParentSHA256' = $($detect.behaviors.parent_details.parent_sha256);
                'ProcessKilled' = $($detect.behaviors.pattern_disposition_details.kill_process);
                'SubProcessKilled' = $($detect.behaviors.pattern_disposition_details.kill_subprocess);
                'ParentKilled' = $($detect.behaviors.pattern_disposition_details.kill_parent);
                'QuarantineMachine' = $($detect.behaviors.pattern_disposition_details.quarantine_machine);
                'QuarantineFile' = $($detect.behaviors.pattern_disposition_details.quarantine_file);
                'OperationBlocked' = $($detect.behaviors.pattern_disposition_details.operation_blocked);
                'ProcessBlocked' = $($detect.behaviors.pattern_disposition_details.process_blocked);
                'RegistryOperationBlocked' = $($detect.behaviors.pattern_disposition_details.registry_operation_blocked);
                'CriticalProcessDisabled' = $($detect.behaviors.pattern_disposition_details.critical_process_disabled);
                'FSOperationBlocked' = $($detect.behaviors.pattern_disposition_details.fs_operation_blocked);
                }
                Write-Host "[+] Found detection for $hostname" -ForegroundColor Yellow
                $detection = New-Object -TypeName PSObject -Property $props
                $detection.PSObject.TypeNames.Insert(0,'TCERT.DetectionInfo')
                if ($script:OutType -eq "Export-TXT") {
                    Write-Host "[+] Appending detection for $computer to text file" -ForegroundColor Yellow
                    Write-Host
                    $detection | Out-File "$script:OutPath\$script:OutFile-detections.txt" -Append
                #} elseif ($script:OutType -eq "Export-Falcon") {
                # Export-FalconReport not working for detections due to field names not matching between detections. 
                #    Try
                #    {
                #        #PSFalcon API command - Export-FalconReport
                #        $detect | Export-FalconReport -Path "$script:OutPath\$script:OutFile-FalconReport-Detections.csv" -ErrorAction SilentlyContinue
                #    }
                #    Catch
                #    {
                #        Write-Host "[!] Error: Could not write Falcon Report for $hostname." -ForegroundColor Red
                #        $_.Exception.ToString()
                #        $error[0] | Format-List -Force
                #        Pause
                #    }
                } else {
                    Try
                    {
                        Write-Host "[+] Appending detection for $hostname to CSV file" -ForegroundColor Yellow
                        Write-Host
                        $detection | Export-CSV "$script:OutPath\$script:OutFile-detections.csv" -Append -NoTypeInformation
                    }
                    Catch
                    {
                        Write-Host "[!] Error: Unable to add detection for $hostname to report. " -ForegroundColor Red
                        $_.Exception.ToString()
                        $error[0] | Format-List -Force
                        Pause
                    }
                }
            }
        }
    }
    Pause
}

#Function contains all hosts in HostIDList
#PSFalcon API command - Invoke-FalconHostAction -Name contain
Function Start-Containment() {
    if ($script:HostTable.count -eq 0) {
        Write-Host "[!] No HostIDs. Enter a list of hosts and then search for HostIDs before containment" -ForegroundColor Red
        Pause
        Start-ContainmentMenu
    } elseif ($script:HostTable.count -lt 25) {
        Write-Host "[!] Containment will be IMPOSED on the following hosts: " -ForegroundColor Red
        foreach ($ID in $script:HostIDList) {
            Write-Host "$ID : $($script:HostTable[$ID])"
        }
    } elseif ($script:HostTable.count -gt 24) {
        Write-Host "[!] More than 25 hosts will be contained (too many to show on screen)" -ForegroundColor Red
    }
    Write-Host "[+] This action must be reviewed prior to being run. Has this been reviewed?" -ForegroundColor Yellow
    $input = ''
    while ($input -ne 'n' -And $input -ne 'y') {
        $input = Read-Host "[Y]es\[N]o"
        switch ($input) {
            'y' {
                    Write-Host "[+] Type 'containme' to confirm containment or 'q' to quit" -ForegroundColor Yellow
                    do 
                    {
                        $selection = Read-Host "[PowerStrike > Main > Containment]"
                        switch ($selection) {
                            'containme' 
                            {
                                foreach ($aid in $script:HostIDList) 
                                {
                                    Write-Host "[+] Starting containment for $aid" -ForegroundColor Yellow
                                    Try 
                                    {
                                        #PSFalcon API command - Invoke-FalconHostAction -Name contain
                                        Invoke-FalconHostAction -Name contain -Ids $aid -ErrorAction SilentlyContinue | Out-Null
                                        Write-Host "[+] Contained $aid" -ForegroundColor Yellow

                                    }
                                    Catch 
                                    {
                                        Write-Host "[!] There has been an error in containment. Host with $aid has not been contained" -ForegroundColor Red
                                        $_.Exception.ToString()
                                        $error[0] | Format-List -Force
                                        Pause
                                    }
                                }
                                Start-ContainmentMenu
                            }
                            'q' 
                            {
                            Start-ContainmentMenu
                            }   
                        }
                    }
                    until ($selection -eq 'q')
                }
            'n' {
                    Start-ContainmentMenu
                }
        }
    }
    Pause
    Start-ContainmentMenu
}

#Function lifts containment all hosts in HostIDList
#PSFalcon API command - Invoke-FalconHostAction -Name lift_containment
Function Stop-Containment() {
    if ($script:HostTable.count -eq 0) {
        Write-Host "[!] No HostIDs. Enter a list of hosts and then search for HostIDs before lifting containment" -ForegroundColor Red
        Pause
        Start-ContainmentMenu
    } elseif ($script:HostTable.count -lt 25) {
        Write-Host "[!] Containment will be LIFTED on the following hosts: " -ForegroundColor Red
        foreach ($ID in $script:HostIDList) {
            Write-Host "$ID : $($script:HostTable[$ID])"
        }
    } elseif ($script:HostList.count -gt 24) {
        Write-Host "[!] More than 25 hosts will have containment lifted (too many to show on screen)" -ForegroundColor Red
    }
    Write-Host "[+] This action must be reviewed prior to being run. Has this been reviewed?" -ForegroundColor Yellow
    $input = ''
    while ($input -ne 'n' -And $input -ne 'y') {
        $input = Read-Host "[Y]es\[N]o"
        switch ($input) {
            'y' {
                    Write-Host "[+] Type 'liftcontainment' to confirm lifting containment or 'q' to quit" -ForegroundColor Yellow
                    do 
                    {
                        $selection = Read-Host "[PowerStrike > Main > Containment]"
                        switch ($selection) {
                            'liftcontainment' 
                            {
                                foreach ($aid in $script:HostIDList) {
                                    Write-Host "[+] Lifting containment for $aid" -ForegroundColor Yellow
                                    Try 
                                    {
                                        #PSFalcon API command - Invoke-FalconHostAction
                                        Invoke-FalconHostAction -Name lift_containment -Id $aid -ErrorAction SilentlyContinue | Out-Null
                                        Write-Host "[+] Containment lifted for $aid" -ForegroundColor Yellow
                                    }
                                    Catch 
                                    {
                                        Write-Host "[!] Error: There has been an error in lifting containment. Host with $aid remains contained" -ForegroundColor Red
                                        $_.Exception.ToString()
                                        $error[0] | Format-List -Force
                                        Pause
                                    }
                                }
                                Start-ContainmentMenu
                            }
                            'q' 
                            {
                                Start-ContainmentMenu
                            }   
                        }
                    }
                    until ($selection -eq 'q')
                }
            'n' {
                    Start-ContainmentMenu
                }
        }
    }
    Pause
    Start-ContainmentMenu
}

#Obtain a script-wide batch ID for an RTR session
#PSFalcon API command - Start-FalconSession
function Get-BatchID() {
    Write-Host "[+] Obtaining RTR Batch ID" -ForegroundColor Yellow
    Try 
    {
        #store current time for batch timeout (10 mins)
        $script:BatchTime = Get-Date
        #PSFalcon API command - Start-FalconSession
        $script:BatchID = Start-FalconSession -HostIds $script:HostIDList -QueueOffline:$True -ErrorAction SilentlyContinue
        Write-Host "[+] BatchID $($script:BatchID.batch_id) obtained successfully" -ForegroundColor Yellow
    }
    Catch 
    {
        Write-Host "[!] Error: BatchID could not be obtained." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
        Start-RealTimeResponseMenu
    }
}

#Checks duration of current session to see if batchid requires refreshing
function Check-BatchID() {
    if (!$script:BatchID) {
        Write-Host "[!] You need to configure a RTR Batch ID before proceeding" -ForegroundColor Red
        Pause
        Start-RealTimeResponseMenu
    }
    #Get current time
    $currenttime = Get-Date
    $duration = $currenttime - $script:BatchTime
    if ($($duration.TotalMinutes) -gt 10 ) {
        Write-Host "[!] Batch ID expired. Obtaining Batch ID." -ForegroundColor Red
        Get-BatchID
    } else {
        $expire = 10
        $timeleft = $expire - $($duration.TotalMinutes)
        #Write-Host "[+] Batch expires in $timeleft minutes." -ForegroundColor Yellow
    }
}

#Refreshes batch-id to maintain current session
#PSFalcon API command - Update-FalconSession
function Refresh-BatchID() {
    Check-BatchID
    Try
    {
        #store current time for batch timeout (10 mins)
        $script:BatchTime = Get-Date
        #PSFalcon API command - Update-FalconSession
        Update-FalconSession -BatchId $($script:BatchID.batch_id) -QueueOffline:$True -ErrorAction SilentlyContinue | Out-Null
    }
    Catch
    {
        Write-Host "[!] Error: BatchID could not be refreshed." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
        Start-RealTimeResponseMenu
    }
}

#Removes a host from HostList, HostIDList, and current BatchID
#PSFalcon API command - Get-FalconHost, Update-FalconSession
function Remove-HostID() {
    Write-Host "[!] This will remove a workstation from scope for all functions." -ForegroundColor Red
    if ($script:HostList.count -eq '1'){
        #HostList array contains one host
        Write-Host "[!] Only one host in scope. $($script:HostList[0]) cannot be removed." -ForegroundColor Red
        Pause
    } else {
        Try
        {
            #Get computer name from hostlist
            Set-Computer
            #remove selected computer from hostlist
            Write-Host "[+] Removing $script:hostname from HostList" -ForegroundColor Yellow
            $script:HostList = $script:HostList | Where-Object { $_ -ne $script:hostname }
            #remove ID from HostIDList
            Write-Host "[+] Removing $script:aid from HostIDList." -ForegroundColor Yellow
            $script:HostIDList = $script:HostIDList | Where-Object { $_ -ne $script:aid }
            #remove from HostTable
            $script:HostTable.remove("$script:aid")
            #Remove ID from Batch
            if ($script:BatchID) {
                Write-Host "[+] Removing $script:hostname - $script:aid from BatchID $($script:BatchID.batch_id)" -ForegroundColor Yellow
                #PSFalcon API command - Update-FalconSession
                Update-FalconSession -BatchId $($script:BatchID.batch_id) -HostsToRemove $script:aid -ErrorAction SilentlyContinue | Out-Null
                $script:BatchTime = Get-Date
            }
            Remove-HostID
        }
        Catch
        {
            Write-Host "[!] Error: BatchID could not be updated." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    }
}

#Function loops through HostList for user to select one host
function Set-Computer() {
    $script:results = @()
    if ($script:HostList.count -eq '1'){
        #HostList array contains one host
        $script:hostname = $script:HostList[0]
        Write-Host "[+] Only one host in scope. $($script:HostList[0]) selected. Searching for AID(s)" -ForegroundColor Yellow
        $script:results = ($script:HostTable.GetEnumerator() | Where {$_.Value -contains "$script:hostname"}).name
        #Check how many AIDs $script:hostname has in scope.
        if ($script:results.count -eq 0) {
            Write-Host "[!] Unable to locate AID in HostTable." -ForegroundColor Red
            Pause
        } elseif ($script:results.count -eq 1) {
            $script:aid = $script:results
            Write-Host "[+] Found $script:aid for Hostname: $script:hostname." -ForegroundColor Yellow
        } elseif ($script:results.count -gt 1) {
            Set-AID
        }
    } else {
        Try
        {   
            #Loops throuh HostList printing array index and computer name
            for($i=0;$i-le $script:HostList.length-1;$i++) {"{0}: {1}" -f $i,$script:HostList[$i]}
            Write-Host 
            $input = ''
            #While input not null prompt user for index
            While ($input.length -eq 0) {
                $input = Read-Host -Prompt "Select a Host ('q' to quit)"
            }
            if ($input -eq 'q') {
                Break
            } elseif ($input -NotMatch "^\d+$") {
                Write-Host "[!] Input must be an integer." -ForegroundColor Red
                Set-Computer
            } elseif ($input -gt $script:HostList.length) {
                Write-Host "[!] Input not in range." -ForegroundColor Red
                Set-Computer
            } else {
                $script:hostname = $script:HostList[$input]
                Write-Host "[+] $($script:HostList[$input]) selected. Searching for AID(s)" -ForegroundColor Yellow
                $script:results = ($script:HostTable.GetEnumerator() | Where {$_.Value -contains "$script:hostname"}).name
                #Check how many AIDs $script:hostname has in scope.
                if ($script:results.count -eq 0) {
                    Write-Host "[!] Unable to locate AID in HostTable." -ForegroundColor Red
                    Pause
                } elseif ($script:results.count -eq 1) {
                    $script:aid = $script:results
                    Write-Host "[+] Found $script:aid for Hostname: $script:hostname." -ForegroundColor Yellow
                } elseif ($script:results.count -gt 1) {
                    Set-AID
                }
            }
        }
        Catch
        {
            Write-Host "[!] Error: Failed to select a host from HostList." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    }
}

#Takes array of AIDs and prints them
function Set-AID() {
    Try
    {
        Write-Host "[!] Warning. Hostname has $($script:results.count) AIDs in scope." -ForegroundColor Red
        #Loops throuh $script:results printing array index and computer name
        for($i=0;$i-le $script:results.length-1;$i++) {"{0}: {1}" -f $i,$script:results[$i]}
        Write-Host
        $input = ''
        #While input not null prompt user for index
        While ($input.length -eq 0) {
            $input = Read-Host -Prompt "Select an AID ('q' to quit)"
        }
        if ($input -eq 'q') {

        } elseif ($input -NotMatch "^\d+$") {
            Write-Host "[!] Input must be an integer." -ForegroundColor Red
            Set-AID
        } elseif ($input -gt $script:HostIDList.length) {
            Write-Host "[!] Input not in range." -ForegroundColor Red
            Set-AID
        } else {
            $script:aid = $script:results[$input]
            Write-Host "[+] AID: $script:aid selected for Hostname: $script:hostname." -ForegroundColor Yellow
        }
    }
    Catch
    {
        Write-Host "[!] Error: Failed to select an AID from results." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Obtains a list of Falcon RTR script IDs ($script:RTRScriptId) and loads details into $script:customInfo
#PSFalcon API command - Get-FalconScript
function Get-ScriptId() {
    Try
    {
        Write-Host "[+] Obtaining list of Script IDs" -ForegroundColor Yellow
        #PSFalcon API cpmmand - Get-FalconScript
        $script:RTRScriptId = Get-FalconScript -ErrorAction SilentlyContinue
    }
    catch 
    {
        Write-Host "[!] Error: Failed to obtain script IDs." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
    if ($script:RTRScriptId) {
        Try
        {
            Write-Host "[+] Searching for scripts based on Script IDs" -ForegroundColor Yellow
            #PSFalcon API cpmmand - Get-FalconScript
            $script:customInfo = Get-FalconScript -Ids $script:RTRScriptId -ErrorAction SilentlyContinue
        }
        catch 
        {
            Write-Host "[!] Error: Failed to obtain script info from IDs." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    }
}

#Function to set the variables required for standard RTR commands
function Set-RealTimeResponseCommands() {
    Write-Host
    Write-Host "[+] For a list of valid RTR commands, type 'help' at anytime. Type 'q' to quit." -ForegroundColor Yellow
    $command = Read-Host "Enter your RTR command for hosts in scope"
    if ($command -eq 'help') {
        Show-RTRHelp
    }
    elseif ($command -eq 'q') {
        Write-Host "[+] Returning to RTR Menu" -ForegroundColor Yellow
        Pause
        Start-RealTimeResponseMenu
    }
    elseif ($script:RTRCommandList -notcontains $command) {
        Write-Host "[!] Invalid command" -ForegroundColor Red
        Pause
        Set-RealTimeResponseCommands
    }
    $argument = Read-Host "Enter your additional parameters"
    if ($argument -eq 'help') {
        Show-RTRHelp
    } 
    elseif ($argument -eq 'q') {
        Write-Host "[+] Returning to RTR Menu" -ForegroundColor Yellow
        Pause
        Start-RealTimeResponseMenu
    }
    $script:RTRCommand = $command
    $script:argument = $argument
    Send-RealTimeResponseCommands
    Set-RealTimeResponseCommands
}

#Send a RTR command and output to stdout and file. 
#PSFalcon API command - Invoke-FalconAdminCommand
function Send-RealTimeResponseCommands() {
    #Refresh 10 minute timeout on BatchID
    Refresh-BatchID
    Try 
    {
        #PSFalcon API command - Invoke-FalconAdminCommand
        $script:results = Invoke-FalconAdminCommand -Command $script:RTRCommand -Arguments $script:argument -BatchId $script:BatchID.Batch_id -ErrorAction SilentlyContinue
    }
    Catch 
    {
        Write-Host "[!] Error: Unable to send Falcon Admin Command." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
        Start-RealTimeResponseMenu
    }
    Run-RTRReport
}

#Writes output from RTR commands
function Run-RTRReport() {
    if ($script:results.count -gt 1) {
        for($i=0;$i-le $script:results.count-1;$i++) {
            $DateUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            $DateLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss Local")
            $aid = $($script:results[$i].aid)
            $Hostname = $($script:HostTable[$aid])
            Write-Host
            Write-Host "*** RTR COMMAND START $($script:results[$i].aid) - $Hostname ***" -ForegroundColor Yellow
            Write-Host "RTR Command: $script:RTRCommand $script:argument"
            Write-Host "$DateUTC"
            Write-Host "$DateLocal"
            Write-Host
            Write-Host "StdOut:"
            Write-Host $($script:results[$i].stdout)
            Write-Host 
            Write-Host "Stderr:"
            Write-Host $($script:results[$i].stderr)
            Write-Host 
            Write-Host "Queued: $($script:results[$i].offline_queued)"
            Write-Host
            Write-Host "*** RTR COMMAND END $aid ***" -ForegroundColor Yellow
            Write-Host
            if ($script:OutType -eq "Export-TXT") {
                Try 
                {
                    Add-Content -Path "$script:OutPath\$($script:results[$i].aid).txt" -Value "`n*** RTR COMMAND START: $script:RTRCommand $script:argument ***`n"
                    Add-Content -Path "$script:OutPath\$($script:results[$i].aid).txt" -Value "$DateUTC`n$DateLocal`n"
                    Add-Content -Path "$script:OutPath\$($script:results[$i].aid).txt" -Value "STDOUT`n"
                    $($script:results[$i].stdout) | Out-File "$script:OutPath\$($script:results[$i].aid).txt" -Append -Encoding ascii
                    Add-Content -Path "$script:OutPath\$($script:results[$i].aid).txt" -Value "STDERR`n"
                    $($script:result[$i].stderr) | Out-File "$script:OutPath\$($script:results[$i].aid).txt" -Append -Encoding ascii
                    Add-Content -Path "$script:OutPath\$($script:results[$i].aid).txt" -Value "Queued`n"
                    $($script:results[$i].offline_queued) | Out-File "$script:OutPath\$($script:results[$i].aid).txt" -Append -Encoding ascii
                    Add-Content -Path "$script:OutPath\$($script:results[$i].aid).txt" -Value "`n*** RTR COMMAND END ***`n"
                    Write-Host "[+] Output data written to '$($script:results[$i].aid).txt' at '$script:OutPath'" -ForegroundColor Yellow
                }
                Catch 
                {
                    Write-Host "[!] Error: No text output data was written. Check you have configured a path or have writable access to that location" -ForegroundColor Red
                    $_.Exception.ToString()
                    $error[0] | Format-List -Force
                    Pause
                }
            }
            else {
                Try
                {
                    $props = [ordered]@{
                        'UTC' = $DateUTC
                        'Local_Time' = $DateLocal
                        'Query_Time' = $($script:results[$i].query_time)
                        'AID' = $($script:results[$i].aid)
                        'Hostname' = $Hostname
                        'Command' = $script:RTRCommand
                        'Argument' = $script:argument
                        'STDOUT' = $($script:results[$i].stdout)
                        'STDERROR' = $($script:results[$i].stderr)
                        'Queued_Offline' = $($script:results[$i].offline_queued)
                        'Completed' = $($script:results[$i].complete)
                    }
                    $information = New-Object -TypeName PSObject -Property $props
                    $information.PSObject.TypeNames.Insert(0,'TCERT.RTRInfo')
                    Write-Host "[+] Appending information for aid $($script:results[$i].aid) to CSV file" -ForegroundColor Yellow
                    $information | Export-CSV "$script:OutPath\$script:OutFile-RTR.csv" -Append -NoTypeInformation
                }
                Catch
                {
                    Write-Host "[!] Error: No CSV output data was written. Check you have configured a path or have writable access to that location" -ForegroundColor Red
                    $_.Exception.ToString()
                    $error[0] | Format-List -Force
                    Pause
                }
            }
        }
    } elseif ($script:results) {
        #IF only one result
        $DateUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        $DateLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss Local")
        $aid = $($script:results.aid)
        $Hostname = $($script:HostTable[$aid])
        Write-Host
        Write-Host "*** RTR COMMAND START $($script:results.aid) - $Hostname ***" -ForegroundColor Yellow
        Write-Host "RTR Command: $script:RTRCommand $script:argument"
        Write-Host "$DateUTC"
        Write-Host "$DateLocal"
        Write-Host
        Write-Host "StdOut:"
        Write-Host $($script:results.stdout)
        Write-Host 
        Write-Host "Stderr:"
        Write-Host $($script:results.stderr)
        Write-Host 
        Write-Host "Queued: $($script:results.offline_queued)"
        Write-Host
        Write-Host "*** RTR COMMAND END $aid ***" -ForegroundColor Yellow
        Write-Host
        if ($script:OutType -eq "Export-TXT") {
            Try 
            {
                Add-Content -Path "$script:OutPath\$($script:results.aid).txt" -Value "`n*** RTR COMMAND START: $script:RTRCommand $script:argument ***`n"
                Add-Content -Path "$script:OutPath\$($script:results.aid).txt" -Value "$DateUTC`n$DateLocal`n"
                Add-Content -Path "$script:OutPath\$($script:results.aid).txt" -Value "STDOUT`n"
                $($script:results.stdout) | Out-File "$script:OutPath\$($script:results.aid).txt" -Append -Encoding ascii
                Add-Content -Path "$script:OutPath\$($script:results.aid).txt" -Value "STDERR`n"
                $($script:results.stderr) | Out-File "$script:OutPath\$($script:results.aid).txt" -Append -Encoding ascii
                Add-Content -Path "$script:OutPath\$($script:results.aid).txt" -Value "Queued`n"
                $($script:results.offline_queued) | Out-File "$script:OutPath\$($script:results.aid).txt" -Append -Encoding ascii
                Add-Content -Path "$script:OutPath\$($script:results.aid).txt" -Value "`n*** RTR COMMAND END ***`n"
                Write-Host "[+] Output data written to '$($script:results.aid).txt' at '$script:OutPath'" -ForegroundColor Yellow
            }
            Catch 
            {
                Write-Host "[!] Error: No text output data was written. Check you have configured a path or have writable access to that location" -ForegroundColor Red
                $_.Exception.ToString()
                $error[0] | Format-List -Force
                Pause
            }
        }
        else {
            Try
            {
                $props = [ordered]@{
                    'UTC' = $DateUTC
                    'Local_Time' = $DateLocal
                    'Query_Time' = $($script:results.query_time)
                    'AID' = $aid
                    'Hostname' = $Hostname
                    'Command' = $script:RTRCommand
                    'Argument' = $script:argument
                    'STDOUT' = $($script:results.stdout)
                    'STDERROR' = $($script:results.stderr)
                    'Queued_Offline' = $($script:results.offline_queued)
                    'Completed' = $($script:results.complete)
                }
                $information = New-Object -TypeName PSObject -Property $props
                $information.PSObject.TypeNames.Insert(0,'TCERT.RTRInfo')
                Write-Host "[+] Appending information for aid $($script:results.aid) to CSV file" -ForegroundColor Yellow
                $information | Export-CSV "$script:OutPath\$script:OutFile-RTR.csv" -Append -NoTypeInformation
            }
            Catch
            {
                Write-Host "[!] Error: No CSV output data was written. Check you have configured a path or have writable access to that location" -ForegroundColor Red
                $_.Exception.ToString()
                $error[0] | Format-List -Force
                Pause
            }
        }
    #If results are written to an array
    } elseif (!$script:results) {
        Write-Host "[!] No results from API Query" -ForegroundColor Red
    }
}

#Function to select custom RTR script from list
function Set-CustomScript() {
    Try
    {   
        #Loops throuh scriptinfo.name printing array index and script name
        for($i=0;$i-le $($script:customInfo.count)-1;$i++) {"{0}: {1}" -f $i,$script:customInfo.name[$i]}
        $input= ''
        Write-Host
        #While input not null prompt user for index
        While ($input.length -eq 0) {
            $input = Read-Host -Prompt "Select a script ('q' to quit)"
        }
        if ($input -eq 'q') {
            Start-RealTimeResponseMenu
        } elseif ($input -NotMatch "^\d+$") {
            Write-Host "[!] Input must be an integer." -ForegroundColor Red
            Set-CustomScript
        #} elseif ($input -gt $($script:customInfo.count)) {
        #    Write-Host "[!] Input out of range." -ForegroundColor Red
        #    Set-CustomScript
        } else {
            $script:selectedCustom = $script:customInfo.name[$input]
            Write-Host "[+] $($script:customInfo.name[$input]) selected" -ForegroundColor Yellow
        }
    }
    Catch
    {
        Write-Host "[!] Error: Failed to select a custom script from script ID." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
        Start-CustomScriptMenu
    }
}

#Function to print information about a custom RTR script
function Get-ScriptInfo() {
    #Runs function to select custom scripts
    Set-CustomScript
    #Prints the detailed information of selected custom script
    $info = $script:customInfo | Where-Object {$_.name -eq $script:selectedCustom}
    Write-Host "ID: $($info.id)"
    Write-Host "Name: $($info.name)"
    Write-Host "Description: $($info.description)"
    Write-Host "Created By: $($info.created_by)"
    Write-Host "Created: $($info.created_timestamp)"
    Write-Host "Modified By: $($info.modified_by)"
    Write-Host "Modified: $($info.modified_timestamp)"
    Write-Host "Script: "
    Write-Host $($info.content)
    Pause
}

#Function to set variables required to run custom scripts in current RTR Batch
function Run-CustomScripts() {
    #Choose a custom script
    Set-CustomScript
    #Provide additional agruments
    $parameter = Read-Host "Parameter"
    #Send Real Time Response command with runscript and custom script name
    $script:RTRCommand = 'runscript'
    $script:argument = "-CloudFile=$script:selectedCustom -CommandLine=$parameter"
    Send-RealTimeResponseCommands
    Pause
}

#Runs a custom script against a large number of hosts.
#PSFalcon API cpmmand - Invoke-FalconRTR -Command 'runscript'
function Run-ScriptBulk() {
    #Choose a custom script
    Set-CustomScript
    #Provide additional agruments
    $parameter = Read-Host "Parameter"
    #Send Real Time Response command with runscript and custom script name
    $script:RTRCommand = 'runscript'
    $script:argument = "-CloudFile=$script:selectedCustom -CommandLine=$parameter"
    ForEach ($id in $script:HostIDList) 
    {
        Try 
        {
            $script:results = Invoke-FalconRTR -Command $script:RTRCommand -Arguments $script:argument -HostIds $id -QueueOffline $true
            Run-RTRReport
        }
        Catch 
        {
            Write-Host "[!] Error: Unable to send runscript command for AID:$id." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
        }
    }
    
}

#Initiate a KAPE collection across the batch ID
#PSFalcon API command - invoke-FalconAdminCommand
function Start-KAPECollection() {
    if (!$script:BatchID) {
        Write-Host "[!] You need to configure a RTR Batch ID before proceeding" -ForegroundColor Red
        Pause
        Start-RealTimeResponseMenu
    }
    Refresh-BatchID
    Write-Host "[+] KAPE collection will commence on Batch ID $($script:BatchID.Batch_id)" -ForegroundColor Yellow
    Pause
    Try 
    {
        Write-Host "[+] Changing directories to C:\Windows\Temp" -ForegroundColor Yellow
        invoke-FalconAdminCommand -Command cd -Arguments "C:\Windows\Temp" -BatchId $($script:BatchID.Batch_id) -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 5
        Write-Host "[+] Copying RTR.exe to host(s)" -ForegroundColor Yellow
        invoke-FalconAdminCommand -Command put -Arguments "RTR.exe" -BatchId $($script:BatchID.Batch_id) -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 10
        Write-Host "[+] Executing KAPE on host(s)" -ForegroundColor Yellow
        invoke-FalconAdminCommand -BatchId $($script:BatchID.Batch_id) -Command runscript -Arguments "-CloudFile=KAPE_collection_full.ps1 -timeout=200000" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Complete. Collection time will vary according to data on host(s)" -ForegroundColor Yellow
        Pause
    }
    Catch 
    {
        Write-Host "[!] Error: Unable to issue Falcon Admin Command." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Check on KAPE collection by looking for completed ZIP file in C:\Windows\Temp\RTR\Collect. NB This will utilise a different batch ID.
#PSFalcon API command - Get-FalconHost, Start-FalconSession, Invoke-FalconAdminCommand
function Get-KAPECollectionStatus() {
    #Choose a computer from HostList and set script:aid/script:computer
    Set-Computer
    Write-Host "[+] Checking if KAPE ZIP file has been created on $script:hostname" -ForegroundColor Yellow
    Try
    {
        #Start new session for selected computer
        #PSFalcon API command - Start-FalconSession
        $statusBatchID = Start-FalconSession -HostId $script:aid -ErrorAction SilentlyContinue
    }
    Catch 
    {
        Write-Host "[!] Error: Unable to obtain new session." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
    if ($statusBatchID) {
        Write-Host "[+] New BatchID $($statusBatchID.session_id) obtained for $script:hostname" -ForegroundColor Yellow
        do 
        {
            Write-Host "[+] Checking folder C:\Windows\Temp\RTR\Collect" -ForegroundColor Yellow
            Try
            {
                #PSFalcon API command - Invoke-FalconAdminCommand
                $CloudID = Invoke-FalconAdminCommand -Command ls -Arguments "C:\Windows\Temp\RTR\Collect" -SessionId $($statusBatchID.session_id) -ErrorAction SilentlyContinue
                $counter = 0
                do 
                {
                    #PSFalcon API command - Confirm-FalconAdminCommand
                    $output = Confirm-FalconAdminCommand -CloudRequestId $($CloudID.cloud_request_id) -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 5
                    $counter += 1
                } until ($output.complete -eq $True -Or $counter -eq 5)
            }
            Catch
            {
                Write-Host "[!] Error: Unable to confirm Falcon Admin Command." -ForegroundColor Red
                $_.Exception.ToString()
                $error[0] | Format-List -Force
                Pause
            }
            
        }
        #Example KAPE format 2020-07-07T011121_collection.zip - previous collections will trigger a collection completed response. 
        until (($output.stdout -match "\d{4}-\d{2}-\d\dT\d{6}_collection\.zip") -Or ($counter -eq 5)) 
        if ($counter -eq 5) {
            Write-Host "[!] No ZIP file located. Either KAPE failed, hasn't run on this host, or is still processing." -ForegroundColor Red
        }
        else {
            Write-Host "[+] Located ZIP file matching KAPE format at C:\Windows\Temp\RTR\Collect" -ForegroundColor Yellow
            Write-Host    
        }
        Pause
        Start-RealTimeResponseMenu
    }
    
}

#Send a Custom PowerShell command via RTR to hosts
function Send-CustomPowerShell() {
    #Enter PowerShell script
    $customPS = Read-Host "Enter your custom PowerShell as you would in RTR GUI ('q' to quit)"
    if ($customPS -eq 'q') {
        Start-RealTimeResponseMenu
    }
    #Check if user input contains at lease 1 valid powershell command
    $valid = 0
    $customPS -Split " " | ForEach-Object { 
        if (Get-Command $_ -errorAction SilentlyContinue) {
            $valid += 1
        }
    }
    #If PowerShell command found, set variables required to run script
    if ($valid -gt 0) {
        $script:RTRCommand = 'runscript'
        $script:argument = "-Raw=``````$($customPS)``````"
        Write-Host "[+] Sending Customer Powershell $customPS to hosts in BatchID $($script:BatchID.batch_id)" -ForegroundColor Yellow
        Send-RealTimeResponseCommands
        Send-CustomPowerShell
    } else {
        Write-Host "[!] No valid PowerShell commands found." -ForegroundColor Red
        Send-CustomPowerShell
    }
}

#Function to download Falcon Queued Commands report
#PSFalcon API Command - Get-FalconQueue
function Get-FalconQueuedReport() {
    $filter = "7"
    $filter = Read-Host "Enter the numbers of days to filter on: (default filter 7 days)"
    Write-Host "[+] Obtaining report..." -ForegroundColor Yellow
    Try 
    {
        #PSFalcon API Command - Get-FalconQueue
        Get-FalconQueue -Days $filter -ErrorAction SilentlyContinue | Out-Null
        Move-Item -Path FalconQueue* -Destination $script:OutPath
        Pause
    }
    Catch 
    {
        Write-Host "[!] Falcon Queued Report could not be obtained." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#function to download Queued get request
function Get-FalconQueuedFile() {
    $SessionID = ''
    $SessionID = Read-Host "Enter a session ID: ('q' to quit)"
    If ($SessionID -eq 'q') {
        Start-MainMenu
    } Elseif ($sessionID -Match "\w{8}\-\w{4}\-\w{4}\-\w{4}\-\w{12}") {
        $script:sessionID = $sessionID
        Get-FalconFile
    } else {
    Write-Host "[!] Invalid Session ID." -ForegroundColor Red
    Get-FalconQueuedFile
    }
}

#Download a file from a host to your workstation
#PSFalcon API command - Get-FalconHost, Invoke-FalconRTR, Confirm-FalconGetFile, Receive-FalconGetFile
function Get-FilefromCloud() {
    #Choose a computer from HostList
    Set-Computer
    $source = Read-Host "Enter the full path for source file (e.g. C:\Windows\Temp\RTR\Collect\2020-07-07T005319_collection.zip)('q' to quit)"
    if ($source -eq 'q') {
        Start-RealTimeResponseMenu
    }
    Try
    {
        #PSFalcon API command - Invoke-FalconRTR
        $getrequest = Invoke-FalconRTR -Command get -Arguments $source -HostIds $($script:aid) -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
    }
    Catch 
    {
        Write-Host "[!] Error: Requesting file from host." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
        Start-RealTimeResponseMenu
    }
    Try
    {
        #Check if request was not successful offer to queue offline
        if ($($getrequest.complete) -eq $False) {
            Write-Host "[!] RTR unable to download file. Host offline." -ForegroundColor Red
            do {
                $queue = Read-Host "Would you like to queue the request until the host is online? Y/N"
                switch ($queue)
                {
                    'y' {
                        #PSFalcon API command - Invoke-FalconRTR
                        $getrequest = Invoke-FalconRTR -Command get -Arguments $source -HostIds $($script:aid) -QueueOffline:$True -ErrorAction SilentlyContinue
                        Write-Host "[+] Request for file in offline queued. Session ID - $($getrequest.session_id)" -ForegroundColor Yellow
                        Pause
                        Start-RealTimeResponseMenu
                        }
                    'n' {
                        Start-RealTimeResponseMenu
                        }
                }
            } until ($queue -eq 'n')
        }
        Write-Host "[+] RTR Get request sent to $source for AID $aid" -ForegroundColor Yellow
        Write-Host "[+] Get Command Session ID: $($getrequest.session_id)" -ForegroundColor Yellow
        Write-Host
        $script:sessionID = $($getrequest.session_id)
        Get-FalconFile
    }
    Catch
    {
        Write-Host "[!] Error: Unable to confirm get request." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
    }
    Pause
}

#Downloads file from cloud
function Get-FalconFile() {
    Try
    {
        #Loop until $request.sha256 populated, file will be ready to download
        #PSFalcon API command - Confirm-FalconGetFile
        $request = Confirm-FalconGetFile -SessionID $script:sessionID -ErrorAction SilentlyContinue
        Start-Sleep 5
        if (!($($request.sha256))) {
            do {
                #PSFalcon API command - Confirm-FalconGetFile
                $request = Confirm-FalconGetFile -SessionID $script:sessionID -ErrorAction SilentlyContinue
                Write-Host "[+] File not ready, pausing for 30 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 30
            } until ($($request.sha256).length -gt 0)
        }
        Write-Host "[+] Obtaining SHA256 of target file: $($request.sha256)" -ForegroundColor Yellow
        Write-Host
        Set-Dest
        Write-Host "[+] Destination set to $script:dest" -ForegroundColor Yellow
        Pause
        Write-Host "[+] Downloading file to $script:dest. This may take time depending on the size." -ForegroundColor Yellow
        #PSFalcon API command - Receive-FalconGetFile
        Receive-FalconGetFile -SessionId $($request.session_id) -Sha256 $($request.sha256) -Path $script:dest
        Write-Host
        if (Test-Path $script:dest)
        {
            $LastLength = 1
            $NewLength = (Get-Item $script:dest).length
                while ($NewLength -ne $LastLength) 
                {
                Write-Host "[+] Checking download progress..." -ForegroundColor Yellow
                Write-Host
                $LastLength = $NewLength
                Start-Sleep -Seconds 5
                $NewLength = (Get-Item $script:dest).length
                }
            Write-Host "[+] File Download complete." -ForegroundColor Yellow
            $newhash = Get-FileHash -Algorithm SHA256 $script:dest
            Write-Host "[+] Original RTR File Hash: $($request.sha256.ToUpper())" -ForegroundColor Yellow
            Write-Host "[+] Downloaded 7z Hash: $($newhash.hash.ToUpper())" -ForegroundColor Yellow
            Write-Host "[+] Different hashes are expected (original vs compressed 7z)" -ForegroundColor Yellow
        }
        else 
        {
            Write-Host "[!] There has been a download error. Check the path and try again." -ForegroundColor Red
        }
        Pause
    }
    Catch
    {
        Write-Host "[!] Error: Unable to download file from CrowdStrike." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
}

#Set destination for Get file requests
function Set-Dest {
    $input = Read-Host "Enter the full path and filename of the destination 7z file (e.g. C:\temp\output.7z)"
    #split dest to path
    $path = Split-Path -Path $input
    #test path, if it doesn't exist, create it
    if (!(Test-Path $path -PathType Container)) {
        Write-Host "[+] Attempting to create $path" -ForegroundColor Yellow
        Try 
        {
            New-Item -Path $path -ItemType Directory | Out-Null
            Write-Host "[+] $path created successfully" -ForegroundColor Yellow
            $script:dest = $input
        }
        Catch 
        {
            Write-Host "[!] Error: Unable to create $path. Please ensure you have write permissions." -ForegroundColor Red
            $_.Exception.ToString()
            $error[0] | Format-List -Force
            Pause
            Set-Dest
        }
    } else {
        $script:dest = $input
    }
}

#Takes user input for Client ID and Secrect Key. No validation on input
function Set-ThreatCreds() {
    Write-Host "[!] Warning! Threat Graph API uses legacy API credentials." -ForegroundColor Yellow
    $script:clientid = Read-Host "Enter you Client ID"
    $script:secret = Read-Host "Enter you Client Secret" -AsSecureString
    $script:ThreatTokenSet = 1
    Write-Host "[+] Credentials stored." -ForegroundColor Yellow
    Pause
    Start-MainMenu
}

#Clears variables for Client ID and Secrect Key.
function Clear-ThreatCreds() {
    Write-Host "[!] Warning! Clearing Threat Graph API Credentials." -ForegroundColor Yellow
    $script:clientid = ''
    $script:secret = ''
    $script:ThreatTokenSet = 0
    Pause
    Start-MainMenu
}

#Takes IOC input and determines if input is domain, md5 or sha256
function Set-IOCManual() {
    $IOC = ''
    Write-Host "Valid IOCs are Domains, MD5 Hashes and SHA256 Hashes" -ForegroundColor Yellow
    While ($IOC -ne 'q') 
    { 
        $IOC = Read-Host "Please type an IOC ('q' to stop)"
        if ($IOC -eq 'q') {
            break
        }
        elseif ($IOC.length -eq 0) {
            Write-Host "[!] IOC cannot be blank." -ForegroundColor Red
        }
        elseif ($IOC.length -lt 4) {
            Write-Host "[!] IOC too short." -ForegroundColor Red
        }
        elseif ($script:IOCTable.keys -notcontains $IOC) {
            Write-Host "[+] Identifying $IOC." -ForegroundColor Yellow
            $script:IOC = $IOC
            Identify-IOC
        }
        elseif ($script:IOCTable.keys -contains $IOC) {
            Write-Host "[!] Duplicate IOC identified. $IOC was not added." -ForegroundColor Red
        }
    }
    Write-Host "[+] PowerStrike IOC scope contains $($script:IOCTable.count) IOCs" -ForegroundColor Yellow
    Write-Host "[+] Returning to Threat Graph Menu." -ForegroundColor Yellow
    Pause
    Start-IOCSearchMenu
}

function Set-IOCFile() {
    $IOCFile = $Null
    $IOCFile = Read-Host "Please enter the full path of the text file (e.g. 'C:\temp\ioc.txt')"
    if (Test-Path $IOCFile -PathType Leaf) {
        ForEach ($line in Get-Content $IOCFile) 
        {
            if ($script:IOCTable.keys -notcontains $line) 
            {
                #Write-Host "[+] Identifying $line" -ForegroundColor Yellow
                $script:IOC = $line
                Identify-IOC
            }
            elseif ($script:IOCTable.keys -contains $line) {
                Write-Host "[!] Duplicate IOC identified. $line was not added." -ForegroundColor Red
            }
            else {
                Write-Host "[!] Error. $line was not added." -ForegroundColor Red
            }
        }
        Write-Host "[+] PowerStrike IOC scope contains $($script:IOCTable.count) IOCs" -ForegroundColor Yellow
    }
    else 
    {
        Write-Host "[!] File $IOCFile not found. Please check" -ForegroundColor Red
    }
    Write-Host "[+] Returning to Threat Graph Menu." -ForegroundColor Yellow
    Pause
    Start-IOCSearchMenu
}   

#Identifies $script:IOC as either a md5 ahsh, sha256 hash or domain and adds it to $script:IOCTable[$IOC].$type
function Identify-IOC() {
    if ($script:IOC -match "^\w{32}$") {
        #md5
        Write-Host "[+] $script:IOC Identified as a MD5 Hash" -ForegroundColor Yellow
        $script:IOCTable.add($script:IOC,"md5")
    } elseif ($script:IOC -match "^\w{64}$") {
        #sha256
        Write-Host "[+] $script:IOC Identified as a SHA256 Hash" -ForegroundColor Yellow
        $script:IOCTable.add($script:IOC,"sha256")
    } else {
        #domain
        Write-Host "[+] $script:IOC Identified as a domain" -ForegroundColor Yellow
        $script:IOCTable.add($script:IOC,"domain")
    }
}

#Prints current contents of IOCTable
function Show-IOC() {
    Write-Host
    Write-Host "Current IOCs in scope:"
    foreach ($IOC in $($script:IOCTable.keys)) {
        Write-Host "$IOC-$($script:IOCTable[$IOC])"
    }
    Write-Host
    Write-Host "[+] Total IOCs: $($script:IOCTable.count)" -ForegroundColor Yellow
}

function Remove-IOC() {
    if ($script:IOCTable.count -eq 1){
        Write-Host "[+] Only one IOC in scope." -ForegroundColor Yellow
        Clear-IOC
    }
    $i = 0
    $tempIOCList = @()
    Write-Host
    Write-Host "Current IOCs in scope:"
    foreach ($IOC in $($script:IOCTable.keys)) {
        Write-Host "$i": "$IOC-$($script:IOCTable[$IOC])"
        $tempIOCList += $IOC
        $i++
    }
    $input = ''
    While ($input.length -eq 0) {
        $input = Read-Host "Please select an IOC to remove ('q' to quit)"
    }
    if ($input -eq 'q') {
        Start-IOCSearchMenu
    } elseif ($input -NotMatch "^\d+$") {
        Write-Host "[!] Input must be an integer." -ForegroundColor Red
        Remove-IOC
    #} elseif ($input -gt $($tempIOCList.count)) {
    #    Write-Host "[!] Input out of range." -ForegroundColor Red
    #    Remove-IOC
    } else {
        Write-Host "[+] $($tempIOCList[$index]) selected. Removing from scope." -ForegroundColor Yellow
        $script:IOCTable.Remove("$($tempIOCList[$index])")
        Remove-IOC
    }
}

function Clear-IOC() {
    Write-Host "[!] Warning. This will clear all IOCs from scope" -ForegroundColor Red
    Show-IOC
    $input = $null
    do
    {
        $input = Read-Host "Do you wish to remove all IOCs? y/n"
        if ($input -eq 'y')
        {
            $script:IOCTable = @{}
            Write-Host "[+] All IOCs removed from scope." -ForegroundColor Yellow
            Pause
            Start-IOCSearchMenu
        } 
        elseif ($input -eq 'n') 
        {
            Start-IOCSearchMenu
        }
        else
        {
            Write-Host "[!] Invalid input." -ForegroundColor Red
        }
        
    } until ($input -eq 'y' -Or $input -eq 'n')
}

function Run-IOCSearch() {
    #store current scope in temp variables and clear scope
    $tempHostIDList = @()
    $tempHostList = @()
    $tempHostTable = @{}
    $tempHostIDList = $script:HostIDList
    $tempHostList = $script:HostList
    $tempHostTable = $script:HostTable
    $script:HostIDList = @()
    $script:HostList = @()
    $script:HostTable = @{}
    $script:IOCResponse = @()
    Try
    {
        #configure web request header, url and method
        #WARNING: Clear text API credentials are in memory at this point
        $secretc = [System.Net.NetworkCredential]::new('', $script:secret).Password 
        $pair = "$($script:clientid):$($secretc)"
        $encodedCreds  = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
        $basicAuthValue = "Basic $encodedCreds"
        $url = 'https://falconapi.crowdstrike.com/threatgraph/combined/ran-on/v1?'
        $Method = 'GET'
        $Header = @{
            'Content-Type' = 'application/json'
            Authorization = $basicAuthValue
        }
        #search for each IOC in $script:IOCTable
        foreach ($IOC in $($script:IOCTable.keys)) {
            #build URI
            $uri = $url+"value=$IOC&type=$($script:IOCTable[$IOC])"
            Try 
            {
                #Send Request
                $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $Header 
                #Add response into array
                $script:IOCResponse += $response.resources
            }
            Catch
            {
                Write-Host "[!] No events found for $IOC." -ForegroundColor Red
            }
        }
    }
    Catch
    {
        Write-Host "[!] Error: Unable to contact API." -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        Pause
    }
    if ($script:IOCResponse) {
        foreach ($data in $script:IOCResponse) {
            #Add ID to scope if not 0's and not already in scope
            if ($($data.device_id) -ne '00000000000000000000000000000000') {
                if ($script:HostIDList -notcontains $($data.device_id)) {
                    $script:filter = $($data.device_id)
                    Identify-Hosts
                }
            }
            #Write IOC data out
            $props = [ordered]@{
                'ID' = $($data.id)
                'AID' = $($data.device_id)
                'Hostname' = $script:hostname
                'CID' =  $($data.customer_id)
                'Object' =  $($data.object_id)
                'Direction' =  $($data.direction)
                'Edge' =  $($data.edge_id)
                'Source' =  $($data.source_vertex_id)
                'Scope' =  $($data.scope)
                'Type' =  $($data.edge_type)
                'Timestamp' =  $($data.timestamp)
                'Path' =  $($data.path)
                'Properties' =  $($data.properties)
            }
            Write-Host "[+] Found event for IOC $($data.object_id)" -ForegroundColor Yellow
            $information = New-Object -TypeName PSObject -Property $props
            $information.PSObject.TypeNames.Insert(0,'TCERT.IOCInfo')
            if ($script:OutType -eq "Export-TXT") {
                Write-Host "[+] Appending information for IOC $($data.object_id) to text file" -ForegroundColor Yellow
                $information | Out-File "$script:OutPath\$script:OutFile-$($data.object_id).txt" -Append
            }
            else {
                Write-Host "[+] Appending information for IOC $($data.object_id) to CSV file" -ForegroundColor Yellow
                $information | Export-CSV "$script:OutPath\$script:OutFile-IOCinfo.csv" -Append -NoTypeInformation
            }
            
        }
    }
    if ($script:HostIDList){
        #Search for host information
        Get-HostInfo
    }
    #Reset HostID List
    $input = $null
    do
    {
        $input = Read-Host "Would you like to add these hosts to PowerSTrike's scope? y/n"
        if ($input -eq 'y')
        {
            #Add previous hosts to scope
            $script:HostIDList += $tempHostIDList
            $script:HostList += $tempHostList
            $script:HostTable += $tempHostTable
            Show-Workstations
        } 
        elseif ($input -eq 'n') 
        {
            #Overwrite scope with previous hosts
            $script:HostIDList = $tempHostIDList
            $script:HostList = $tempHostList
            $script:HostTable = $tempHostTable
            Show-Workstations
        }
        else
        {
            Write-Host "[!] Invalid input." -ForegroundColor Red
        }
        
    } until ($input -eq 'y' -Or $input -eq 'n')
    #Retrun to menu
    Start-IOCSearchMenu
}

#Displays RTR Command Options
function Show-RTRHelp() {
    Write-Host "Real Time Response Command List" -ForegroundColor Yellow
    Write-Host
    Write-Host "cat - Display contents of a file"
    Write-Host "cd - Change the current working directory"
    Write-Host "clear - Clear screen"
    Write-Host "cp - Copy a file or directory"
    Write-Host "encrypt - Encrypt a file with an encryption key."
    Write-Host "env - Get environment variables for all scopes (Machine/User/Process)"
    Write-Host "eventlog - Inspect event logs. Subcommands:-list-view-export-backup."
    Write-Host "filehash - Generate the MD5, and SHA256 hashes of a file"
    Write-Host "getsid - Enumerate local users and Security Identifiers (SID). Used with reg commands."
    Write-Host "history - View History"
    Write-Host "ipconfig - Show network configuration information"
    Write-Host "kill - Kill a process"
    Write-Host "ls - Display the contents of the specified path"
    Write-Host "map - Map an SMB (network) share drive"
    Write-Host "memdump - Dump the memory of a process"
    Write-Host "mkdir Create a new directory NOTE: Newly-created directories are only accessible to members of the host’s Administrator group"
    Write-Host "mount - List available drives (Windows)List or mount available drives (macOS)"
    Write-Host "mv - Move a file or directory"
    Write-Host "netstat - Display network statistics and active connections"
    Write-Host "ps - Display process information"
    Write-Host "put - Put a file onto a remote host"
    Write-Host "reg delete - Delete registry subkeys, keys, or value"
    Write-Host "reg load - Load a user registry hive from disk"
    Write-Host "reg unload - Unload a previously loaded user registry hive"
    Write-Host "reg set - Set registry keys or values"
    Write-Host "reg query - Query a registry subkey or value"
    Write-Host "restart - Restart target system"
    Write-Host "rm - Remove a file or directory"
    Write-Host "run - Run an executable"
    Write-Host "runscript - Run a custom script"
    Write-Host "shutdown - Shutdown target system"
    Write-Host "unmap - Unmap an SMB (network) share drive"
    Write-Host "xmemdump - Dump the complete or kernel memory of a system"
    Write-Host "zip - Compress a file or directory into a zip file"
    Pause
    Set-RealTimeResponseCommands
}

Start-MainMenu

