# Security Log Analyser
Analyzes Windows Security event logs with these features:
1. Password sharing detection
2. Suspicious login time detection (configurable business hours)
3. Brute force attack detection
4. Privileged logon tracking (Event ID 4672)
5. Detailed login/logoff tracking

# How To use
Basic analysis (last 7 days).  
```
powershell -ExecutionPolicy Bypass -File .\AdvancedSecurityLogAnalyzer.ps1
```

Analyze with user-computer mapping and custom business hours.  
```
powershell -ExecutionPolicy Bypass -File .\AdvancedSecurityLogAnalyzer.ps1 -UserComputerMapFile .\users.csv -BusinessHoursStart 7 -BusinessHoursEnd 19
```
Analyze offline EVTX file (30 days range).  
```
 powershell -ExecutionPolicy Bypass -File .\AdvancedSecurityLogAnalyzer.ps1 -EventLogFilePath .\archive.evtx -Days 30
```

Show help.  
```
powershell -ExecutionPolicy Bypass -File .\AdvancedSecurityLogAnalyzer.ps1 -Help
```
