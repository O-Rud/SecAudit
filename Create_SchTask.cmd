schtasks /create /S %1 /TN "Export EventLog to SQL" /RU "" /SC MINUTE /MO 15 /TR "powershell.exe -noprofile -NonInteractive -File \\HOME24.LAN\NETLOGON\SecAudit\Export-EventLog2SQLv3.ps1"