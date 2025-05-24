<#
.SYNOPSIS
    Enhanced Security Event Log Analyzer with Privileged Logon Tracking

.DESCRIPTION
    Analyzes Windows Security event logs with these features:
    - Password sharing detection
    - Suspicious login time detection (configurable business hours)
    - Brute force attack detection
    - Privileged logon tracking (Event ID 4672)
    - Detailed login/logoff tracking
.NOTES
    File Name      : AdvancedSecurityLogAnalyzer.ps1
    Author         : Omar Badawy
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges

.PARAMETER LogPath
    Specifies the event log name (default: "Security")

.PARAMETER Days
    Number of days to analyze (default: 7)

.PARAMETER OutputFile
    Output HTML report path (default: "SecurityAnalysis_<timestamp>.html")

.PARAMETER UserComputerMapFile
    Path to CSV file mapping users to their assigned computers (format: user,computer)

.PARAMETER EventLogFilePath
    Path to .evtx file if analyzing offline logs

.PARAMETER BusinessHoursStart
    Start hour for business hours (0-23, default: 8)

.PARAMETER BusinessHoursEnd
    End hour for business hours (0-23, default: 18)

.EXAMPLE
    # Basic analysis (last 7 days)
    powershell -ExecutionPolicy Bypass -File .\log-analyser-v2.ps1

.EXAMPLE
    # Analyze with user-computer mapping and custom business hours
    powershell -ExecutionPolicy Bypass -File .\log-analyser-v2.ps1 -UserComputerMapFile .\users.csv -BusinessHoursStart 7 -BusinessHoursEnd 19

.EXAMPLE
    # Analyze offline EVTX file (30 days range)
    powershell -ExecutionPolicy Bypass -File .\log-analyser-v2.ps1 -EventLogFilePath .\archive.evtx -Days 30

.EXAMPLE
    # Show help
    powershell -ExecutionPolicy Bypass -File .\log-analyser-v2.ps1 -Help
#>

# Parameters
param (
    [string]$LogPath = "Security",
    [int]$Days = 7,
    [string]$OutputFile = "SecurityLogAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$UserComputerMapFile = $null,
    [string]$EventLogFilePath = $null,
    [int]$BusinessHoursStart = 8,
    [int]$BusinessHoursEnd = 18,
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Get-Help $PSCommandPath -Detailed
    exit
}

# Validate business hours
if ($BusinessHoursStart -lt 0 -or $BusinessHoursStart -gt 23 -or 
    $BusinessHoursEnd -lt 0 -or $BusinessHoursEnd -gt 23) {
    Write-Error "Business hours must be between 0-23"
    exit 1
}

# HTML Report Header
$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Security Log Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; position: sticky; top: 0; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { color: #cc3300; font-weight: bold; }
        .info { color: #0066cc; }
        .scrollable { max-height: 500px; overflow-y: auto; display: block; }
        .suspicious { background-color: #ffcccc; }
        .suspicious-process { background-color: #ffcdd2; }
        .non-windows-process { background-color: #ffcc80; }
    </style>
</head>
<body>
    <h1>Advanced Security Event Log Analysis Report</h1>
    <p>Generated on: $(Get-Date)</p>
    <p>Analyzing logs from: $LogPath for the last $Days days</p>
"@

# HTML Report Footer
$htmlFooter = @"
</body>
</html>
"@

# Initialize HTML content
$htmlContent = $htmlHeader

# Business hours formatting
$startTimeFormatted = (Get-Date -Hour $BusinessHoursStart -Minute 0 -Second 0).ToString("hh:mm tt")
$endTimeFormatted = (Get-Date -Hour $BusinessHoursEnd -Minute 0 -Second 0).ToString("hh:mm tt")

# Function to convert Event ID to meaningful description
function Get-EventDescription {
    param ($EventID)
    switch ($EventID) {
        4624 { "Successful login" }
        4625 { "Failed login" }
        4634 { "Account logged off" }
        4647 { "User initiated logoff" }
        4648 { "A login was attempted using explicit credentials" }
        4672 { "Special privileges assigned to new logon" }
        4768 { "A Kerberos authentication ticket (TGT) was requested" }
        4769 { "A Kerberos service ticket was requested" }
        4776 { "The computer attempted to validate the credentials for an account" }
        4720 { "A user account was created" }
        4722 { "A user account was enabled" }
        4725 { "A user account was disabled" }
        4726 { "A user account was deleted" }
        4738 { "A user account was changed" }
        4740 { "A user account was locked out" }
        default { "Event ID $EventID" }
    }
}

# Function to get logon type description
function Get-LogonTypeDescription {
    param ($LogonType)
    switch ($LogonType) {
        0 { "System" }
        2 { "Interactive (Local logon)" }
        3 { "Network (e.g., file share)" }
        4 { "Batch (Scheduled task)" }
        5 { "Service" }
        7 { "Unlock (Screen unlock)" }
        8 { "NetworkCleartext (Cleartext password)" }
        9 { "NewCredentials (RunAs)" }
        10 { "RemoteInteractive (RDP)" }
        11 { "CachedInteractive (Cached credentials)" }
        default { "Unknown ($LogonType)" }
    }
}

# function Get-ProcessExecutions {
#     param($Events)
    
#     $processExecutions = @()
#     $windowsSystemPaths = @(
#         "C:\Windows\System32"
#     )

#     foreach ($event in $Events) {
#         # Event ID 4688: Process creation
#         if ($event.Id -eq 4688) {
#             $processId = $event.Properties[7].Value 
#             $processName = $event.Properties[5].Value # New Process Name
#             $commandLine = $event.Properties[8].Value # Command Line
#             $parentProcessName = $event.Properties[13].Value
#             $user = $event.Properties[1].Value # SubjectUserName
#             $domain = $event.Properties[2].Value # SubjectDomainName

#             # Determine if process is non-Windows
#             $isWindowsProcess = $windowsSystemPaths | Where-Object { $processName -like "$_*" }

#             $processExecutions += [PSCustomObject]@{
#                 Time = $event.TimeCreated
#                 ProcessID = $processId
#                 Process = $processName
#                 CommandLine = $commandLine
#                 ParentProcess = $parentProcessName
#                 User = "$domain\$user"
#                 IsWindowsProcess = [bool]$isWindowsProcess
#             }
#         }
#     }

#     return $processExecutions
# }


try {
    # Load user-computer mapping if provided
    $userComputerMap = @{}
    $computerUserMap = @{} # Reverse mapping for faster lookup
    if ($UserComputerMapFile -and (Test-Path $UserComputerMapFile)) {
        Write-Progress -Activity "Loading User-Computer Mapping" -Status "Processing file"
        Get-Content $UserComputerMapFile | ForEach-Object {
            $parts = $_ -split ','
            if ($parts.Count -ge 2) {
                $user = $parts[0].Trim().ToLower()
                $computer = $parts[1].Trim().ToLower()
                $userComputerMap[$user] = $computer
                $computerUserMap[$computer] = $user
            }
        }
    }


    # Calculate the time frame
    $startTime = (Get-Date).AddDays(-$Days)
    
    # Get all relevant security events
    Write-Progress -Activity "Collecting Security Events" -Status "Please wait..."
    
    if ($EventLogFilePath -and (Test-Path $EventLogFilePath)) {
        $events = Get-WinEvent -Path $EventLogFilePath -Oldest -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $startTime }
    } else {
        $events = Get-WinEvent -LogName $LogPath -Oldest -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $startTime }
    }
    
    if (-not $events) {
        $htmlContent += "<p class='warning'>No security events found in the specified time frame.</p>"
        $htmlContent += $htmlFooter
        $htmlContent | Out-File -FilePath $OutputFile
        Write-Host "No events found. Report generated at $OutputFile" -ForegroundColor Yellow
        return
    }
    
    # Initialize data structures
    $logonEvents = @{}
    $logoffEvents = @{}
    $passwordSpraying = @{}
    $bruteForceAttempts = @{}
    $suspiciousLogins = @()
    $networkLogons = @()
    $rdpLogons = @()
    $nonBusinessLogons = @()
    $domainAccounts = @()
    $localAccounts = @()
    $systemAccounts = @()
    $privilegedLogons = @()
    $processExecutions = @()
    $windowsSystemPaths = @(
        "C:\Windows\System32"
    )


    # Process events
    $totalEvents = $events.Count
    $processed = 0

    # Process execution analysis
    # $processes = Get-ProcessExecutions -Events $events
    # $nonWindowsProcesses = $processes | Where-Object { -not $_.IsWindowsProcess }
    
    foreach ($event in $events) {
        $processed++
        $percentComplete = ($processed / $totalEvents) * 100
        Write-Progress -Activity "Processing Events" -Status "Analyzing event $processed of $totalEvents" -PercentComplete $percentComplete
       
        # Event ID 4688: Process creation
        if ($event.Id -eq 4688) {
            $processId = $event.Properties[7].Value 
            $processName = $event.Properties[5].Value # New Process Name
            $commandLine = $event.Properties[8].Value # Command Line
            $parentProcessName = $event.Properties[13].Value
            $user = $event.Properties[1].Value # SubjectUserName
            $domain = $event.Properties[2].Value # SubjectDomainName

            # Determine if process is non-Windows
            $isWindowsProcess = $windowsSystemPaths | Where-Object { $processName -like "$_*" }

            $processExecutions += [PSCustomObject]@{
                Time = $event.TimeCreated
                ProcessID = $processId
                Process = $processName
                CommandLine = $commandLine
                ParentProcess = $parentProcessName
                User = "$domain\$user"
                IsWindowsProcess = [bool]$isWindowsProcess
            }
        }
        $nonWindowsProcesses = $processExecutions | Where-Object { -not $_.IsWindowsProcess }

        # Privileged logon events (Event ID 4672)
        if ($event.Id -eq 4672) {
            $privilegedLogons += [PSCustomObject]@{
                Time = $event.TimeCreated
                User = $event.Properties[1].Value # SubjectUserName
                Domain = $event.Properties[2].Value # SubjectDomainName
                Privileges = $event.Properties[4].Value # PrivilegeList
                LogonID = $event.Properties[3].Value # LogonId
            }
            
        }
        # Logon events (4624)
        if ($event.Id -eq 4624) {
            $logonId = $event.Properties[7].Value.ToString()
            $username = $event.Properties[5].Value
            $domain = $event.Properties[6].Value
            $logonType = $event.Properties[8].Value
            $workstation = $event.Properties[11].Value
            $sourceIP = $event.Properties[18].Value
            $timeCreated = $event.TimeCreated

            $logonEvents[$logonId] = [PSCustomObject]@{
                Time = $timeCreated
                LogonID = $logonId
                User = $username
                Domain = $domain
                LogonType = $logonType
                Workstation = $workstation
                SourceIP = $sourceIP
                LogoffTime = $null
            }

            # Check for password sharing
            if ($userComputerMap.Count -gt 0) {
            $workstationLower = $workstation.ToLower()
            if ($computerUserMap.ContainsKey($workstationLower)) {
                $expectedUser = $computerUserMap[$workstationLower]
                $currentUserLower = $username.ToLower()
        
                if ($expectedUser -ne $currentUserLower) {
                    $suspiciousLogins += [PSCustomObject]@{
                        Time = $timeCreated
                        UnauthorizedUser = $username
                        ExpectedUser = $expectedUser
                        Workstation = $workstation
                        SourceIP = $sourceIP
                        LogonType = $logonType
                        Domain = $domain
                    }
                }
            }
        }


            # Check for non-business hours
            $hour = $timeCreated.Hour
            if ($hour -lt $businessStart -or $hour -ge $businessEnd) {
                $nonBusinessLogons += [PSCustomObject]@{
                    Time = $timeCreated
                    User = $username
                    Domain = $domain
                    Workstation = $workstation
                    SourceIP = $sourceIP
                    LogonType = $logonType
                }
            }

            # Categorize by account type
            if ($domain -eq "NT AUTHORITY") {
                $systemAccounts += $logonEvents[$logonId]
            } elseif ($domain -eq $env:COMPUTERNAME -or $domain -eq "WORKGROUP") {
                $localAccounts += $logonEvents[$logonId]
            } else {
                $domainAccounts += $logonEvents[$logonId]
            }

            # Network and RDP logons
            if ($logonType -eq 3) {
                $networkLogons += $logonEvents[$logonId]
            } elseif ($logonType -eq 10) {
                $rdpLogons += $logonEvents[$logonId]
            }
        }
        # Logoff events (4634, 4647)
        elseif ($event.Id -in (4634, 4647)) {
            $logonId = $event.Properties[3].Value.ToString()
            if ($logonEvents.ContainsKey($logonId)) {
                $logonEvents[$logonId].LogoffTime = $event.TimeCreated
            }
        }
        # Failed logins (4625 - potential brute force)
        elseif ($event.Id -eq 4625) {
            $username = $event.Properties[5].Value
            $workstation = $event.Properties[11].Value
            $sourceIP = $event.Properties[19].Value
            $timeCreated = $event.TimeCreated

            if (-not $bruteForceAttempts.ContainsKey($username)) {
                $bruteForceAttempts[$username] = @()
            }
            $bruteForceAttempts[$username] += [PSCustomObject]@{
                Time = $timeCreated
                Workstation = $workstation
                SourceIP = $sourceIP
            }

            # Detect password spraying (multiple users from same IP)
            if (-not $passwordSpraying.ContainsKey($sourceIP)) {
                $passwordSpraying[$sourceIP] = @{}
            }
            if (-not $passwordSpraying[$sourceIP].ContainsKey($username)) {
                $passwordSpraying[$sourceIP][$username] = 0
            }
            $passwordSpraying[$sourceIP][$username]++
        }
    }

    # Generate HTML report sections

    # 1. All Logons with Logoff Times
    $htmlContent += @"
    <h2>All Logon Events with Logoff Times</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Logoff Time</th>
            <th>Logon ID</th>
            <th>Username</th>
            <th>Logon Type</th>
            <th>Workstation</th>
            <th>Domain/Workgroup</th>
            <th>Source IP</th>
        </tr>
"@
    $logonEvents.Values | Sort-Object Time | ForEach-Object {
        $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.LogoffTime)</td><td>$($_.LogonID)</td><td>$($_.User)</td><td>$(Get-LogonTypeDescription $_.LogonType)</td><td>$($_.Workstation)</td><td>$($_.Domain)</td><td>$($_.SourceIP)</td></tr>"
    }
    $htmlContent += "</table></div>"

    # 2. Domain Accounts
    $htmlContent += @"
    <h2>Domain Account Logons</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Logoff Time</th>
            <th>Username</th>
            <th>Logon Type</th>
            <th>Workstation</th>
            <th>Domain</th>
            <th>Source IP</th>
        </tr>
"@
    $domainAccounts | Sort-Object Time | ForEach-Object {
        $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.LogoffTime)</td><td>$($_.User)</td><td>$(Get-LogonTypeDescription $_.LogonType)</td><td>$($_.Workstation)</td><td>$($_.Domain)</td><td>$($_.SourceIP)</td></tr>"
    }
    $htmlContent += "</table></div>"

    # 3. Local Accounts
    $htmlContent += @"
    <h2>Local Account Logons</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Logoff Time</th>
            <th>Username</th>
            <th>Logon Type</th>
            <th>Workstation</th>
            <th>Domain/Workgroup</th>
            <th>Source IP</th>
        </tr>
"@
    $localAccounts | Sort-Object Time | ForEach-Object {
        $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.LogoffTime)</td><td>$($_.User)</td><td>$(Get-LogonTypeDescription $_.LogonType)</td><td>$($_.Workstation)</td><td>$($_.Domain)</td><td>$($_.SourceIP)</td></tr>"
    }
    $htmlContent += "</table></div>"

     # Generate Privileged Logons Table
    if ($privilegedLogons.Count -gt 0) {
        $htmlContent += @"
        <h2>Privileged Logons (Event ID 4672)</h2>
        <div class="scrollable">
        <table >
            <tr>
                <th>Time</th>
                <th>User</th>
                <th>Domain</th>
                <th>Privileges</th>
                <th>Logon ID</th>
            </tr>
"@
        foreach ($logon in $privilegedLogons) {
            $htmlContent += @"
            <tr class='privileged'>
                <td>$($logon.Time)</td>
                <td>$($logon.User)</td>
                <td>$($logon.Domain)</td>
                <td>$($logon.Privileges)</td>
                <td>$($logon.LogonID)</td>
            </tr>
"@
        }
        $htmlContent += "</table></div>"
    } else {
        $htmlContent += "<p class='info'>No privileged logon events found.</p>"
    }

    # 4. System Accounts
    $htmlContent += @"
    <h2>System Account Logons</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Logoff Time</th>
            <th>Username</th>
            <th>Logon Type</th>
            <th>Workstation</th>
            <th>Domain</th>
            <th>Source IP</th>
        </tr>
"@
    $systemAccounts | Sort-Object Time | ForEach-Object {
        $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.LogoffTime)</td><td>$($_.User)</td><td>$(Get-LogonTypeDescription $_.LogonType)</td><td>$($_.Workstation)</td><td>$($_.Domain)</td><td>$($_.SourceIP)</td></tr>"
    }
    $htmlContent += "</table></div>"

    # 5. Network Logons
    $htmlContent += @"
    <h2>Network Logons (Logon Type 3)</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Logoff Time</th>
            <th>Username</th>
            <th>Workstation</th>
            <th>Domain</th>
            <th>Source IP</th>
        </tr>
"@
    $networkLogons | Sort-Object Time | ForEach-Object {
        $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.LogoffTime)</td><td>$($_.User)</td><td>$($_.Workstation)</td><td>$($_.Domain)</td><td>$($_.SourceIP)</td></tr>"
    }
    $htmlContent += "</table></div>"

    # 6. RDP Logons
    $htmlContent += @"
    <h2>Remote Desktop Logons (Logon Type 10)</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Logoff Time</th>
            <th>Username</th>
            <th>Workstation</th>
            <th>Domain</th>
            <th>Source IP</th>
        </tr>
"@
    $rdpLogons | Sort-Object Time | ForEach-Object {
        $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.LogoffTime)</td><td>$($_.User)</td><td>$($_.Workstation)</td><td>$($_.Domain)</td><td>$($_.SourceIP)</td></tr>"
    }
    $htmlContent += "</table></div>"

    # 7. Non-Business Hours Logons
    if ($nonBusinessLogons.Count -gt 0) {
        $htmlContent += @"
        <h2>Non-Business Hours Logons (Outside $($startTimeFormatted)-$($endTimeFormatted))</h2>
        <div class="scrollable">
        <table>
            <tr>
                <th>Logon Time</th>
                <th>Username</th>
                <th>Domain</th>
                <th>Workstation</th>
                <th>Source IP</th>
                <th>Logon Type</th>
            </tr>
"@
        $nonBusinessLogons | Sort-Object Time | ForEach-Object {
            $htmlContent += "<tr><td>$($_.Time)</td><td>$($_.User)</td><td>$($_.Domain)</td><td>$($_.Workstation)</td><td>$($_.SourceIP)</td><td>$(Get-LogonTypeDescription $_.LogonType)</td></tr>"
        }
        $htmlContent += "</table></div>"
    }

    # 8. Password Sharing Detection
    if ($suspiciousLogins.Count -gt 0) {
    $htmlContent += @"
    <h2 class='warning'>Password Sharing Violations Detected</h2>
    <div class="scrollable">
    <table>
        <tr>
            <th>Logon Time</th>
            <th>Unauthorized User</th>
            <th>Expected User</th>
            <th>Workstation</th>
            <th>Domain</th>
            <th>Source IP</th>
            <th>Logon Type</th>
        </tr>
"@
    $suspiciousLogins | Sort-Object Time | ForEach-Object {
        $htmlContent += @"
        <tr class='suspicious'>
            <td>$($_.Time)</td>
            <td><strong>$($_.UnauthorizedUser)</strong></td>
            <td><strong>$($_.ExpectedUser)</strong></td>
            <td>$($_.Workstation)</td>
            <td>$($_.Domain)</td>
            <td>$($_.SourceIP)</td>
            <td>$(Get-LogonTypeDescription $_.LogonType)</td>
        </tr>
"@
    }
    $htmlContent += @"
    </table>
    <p class='warning'>Alert: These logins show potential password sharing violations where users logged into workstations assigned to other employees.</p>
    </div>
"@
}

    # 9. Brute Force Attempts
    if ($bruteForceAttempts.Count -gt 0) {
        $htmlContent += @"
        <h2 class='warning'>Brute Force Attempts</h2>
        <div class="scrollable">
        <table>
            <tr>
                <th>Username</th>
                <th>Attempt Count</th>
                <th>Workstations</th>
                <th>Source IPs</th>
                <th>First Attempt</th>
                <th>Last Attempt</th>
            </tr>
"@
        foreach ($user in $bruteForceAttempts.Keys) {
            $attempts = $bruteForceAttempts[$user]
            if ($attempts.Count -gt 2) {
                $workstations = ($attempts.Workstation | Select-Object -Unique) -join ", "
                $sourceIPs = ($attempts.SourceIP | Select-Object -Unique) -join ", "
                $firstAttempt = ($attempts.Time | Measure-Object -Minimum).Minimum
                $lastAttempt = ($attempts.Time | Measure-Object -Maximum).Maximum                
                $htmlContent += "<tr class='suspicious'><td>$user</td><td>$($attempts.Count)</td><td>$workstations</td><td>$sourceIPs</td><td>$firstAttempt</td><td>$lastAttempt</td></tr>"
            }
        }
        $htmlContent += "</table></div>"
    }

    # 10. Password Spraying Detection
    $sprayingDetected = $passwordSpraying.GetEnumerator() | Where-Object { $_.Value.Count -ge 3 } | Sort-Object { $_.Value.Count } -Descending
    if ($sprayingDetected) {
        $htmlContent += @"
        <h2 class='warning'>Possible Password Spraying Detected</h2>
        <div class="scrollable">
        <table>
            <tr>
                <th>Source IP</th>
                <th>Unique Users Targeted</th>
                <th>Total Attempts</th>
                <th>Targeted Users</th>
            </tr>
"@
        foreach ($ip in $sprayingDetected) {
            $users = $ip.Value.GetEnumerator() | ForEach-Object { "$($_.Key) ($($_.Value) attempts)" }
            $userList = $users -join ", "
            
            $htmlContent += "<tr class='suspicious'><td>$($ip.Name)</td><td>$($ip.Value.Count)</td><td>$($ip.Value.Values | Measure-Object -Sum).Sum</td><td>$userList</td></tr>"
        }
        $htmlContent += "</table></div>"
    }

    # Non-Windows process
    if ($nonWindowsProcesses.Count -gt 0) {
        $htmlContent += @"
        <h2>Non-Windows Process Executions</h2>
        <table>
            <tr>
                <th>Time</th>
                <th>User</th>
                <th>Process ID</th>
                <th>Process</th>
                <th>Command Line</th>
                <th>ParentProcess</th>
            </tr>
"@
        foreach ($proc in $nonWindowsProcesses) {
            $htmlContent += @"
            <tr class="non-windows-process">
                <td>$($proc.Time)</td>
                <td>$($proc.User)</td>
                <td><code>$($proc.ProcessID)</code></td>
                <td>$($proc.Process)</td>
                <td><code>$($proc.CommandLine)</code></td>
                <td><code>$($proc.ParentProcess)</code></td>
            </tr>
"@
        }
        $htmlContent += "</table>"
    }

    # Complete the HTML report
    $htmlContent += $htmlFooter
    $htmlContent | Out-File -FilePath $OutputFile
    
    Write-Host "Security log analysis completed. Report generated at $OutputFile" -ForegroundColor Green
    Invoke-Item $OutputFile
}
catch {
    $errorMessage = $_.Exception.Message
    $htmlContent += "<p class='warning'>Error occurred: $errorMessage</p>"
    $htmlContent += $htmlFooter
    $htmlContent | Out-File -FilePath $OutputFile
    Write-Host "Error occurred: $errorMessage" -ForegroundColor Red
    Write-Host "Partial report generated at $OutputFile" -ForegroundColor Yellow
}