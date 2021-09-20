$extract = "C:\Windows\Temp\RTR.exe -y -oC:\Windows\Temp\RTR"
Invoke-Expression "& $extract"
Start-Sleep -Seconds 5
$collect = "C:\Windows\Temp\RTR\kape.exe --tsource C: --tdest C:\Windows\Temp\RTR\Collect --vhd collection --target 'WindowsDefender,WebBrowsers,EventLogs,EvidenceOfExecution,FileSystem,LnkFilesAndJumpLists,RecycleBinMetadata,RegistryHives,ScheduledTasks,USBDevicesLogs,WBEM,WER'"
Invoke-Expression "& $collect"
