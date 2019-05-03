@echo off
set "logfile=C:\Windows\Temp\finalize-setup.log"
cmd /c winrm quickconfig -q >> %logfile%
cmd /c winrm quickconfig -transport:http >> %logfile%
cmd /c winrm set winrm/config @{MaxTimeoutms="1800000"} >> %logfile%
cmd /c winrm set winrm/config/client @{TrustedHosts="41.185.*"} >> %logfile%
cmd /c winrm set winrm/config/winrs @{MaxMemoryPerShellMB="1024"} >> %logfile%
cmd /c winrm set winrm/config/service @{AllowUnencrypted="true"} >> %logfile%
cmd /c winrm set winrm/config/service/auth @{Basic="true"} >> %logfile%
cmd /c winrm set winrm/config/client/auth @{Basic="true"} >> %logfile%
cmd /c winrm set winrm/config/listener?Address=*+Transport=HTTP @{Port="5985"} >> %logfile%
cmd /c netsh advfirewall firewall add rule name="WinRM (TCP-In)" dir=in action=allow protocol=TCP localport=5985 remoteip=41.185.11.0/24 profile=public >> %logfile%
cmd /c netsh advfirewall firewall add rule name="Allow Incoming Echo Request - ICMPv4-In" protocol=icmpv4:8,any dir=in action=allow >> %logfile%
cmd /C wmic useraccount where "name='admin'" set PasswordExpires=FALSE
cmd /C wmic useraccount where "name='administrator'" set PasswordExpires=FALSE
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v AcceptTrustedPublisherCerts /t REG_DWORD /d 1 /f
cmd /C reg add  "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"	
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer /t REG_DWORD /d 0 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v RescheduleWaitTimeEnabled /t REG_DWORD /d 1 /f
cmd /C reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
cmd /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "DefaultConnectionSettings" /t REG_SZ /d 460000001e00000001000000000000000000000000000000010000000000000018dc31de5756ce0100000000000000000000000000000000 /f
cmd /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 00000000 /f
cmd /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 2 /f
cmd /c reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpCount /t REG_DWORD /d 10 /f
cmd /c reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpType /t REG_DWORD /d 1 /f
cmd /c w32tm /config /manualpeerlist:"za.pool.ntp.org" /syncfromflags:MANUAL
cmd /c net stop W32Time
cmd /c net start W32Time
cmd /c w32tm /query /peers
cscript /b c:\windows\system32\slmgr.vbs /skms KMS_HOST_SERVER
cscript /b c:\windows\system32\slmgr.vbs -ato
::cmd /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f
::cmd /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
::cmd /c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" /v "cadca5fe-87d3-4b96-b7fb-a231484277cc" /t REG_DWORD /d 0 /f
cmd /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 00000000 /f 
cmd /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 00000001 /f
cmd /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 00000001 /f >> %logfile%
cmd /c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" /v allow_unencrypted /t REG_DWORD /d 00000001 /f
cmd /c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" /v auth_basic /t REG_DWORD /d 00000001 /f	
::cmd /c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 0000000 /f
cmd /c reg Add HKLM\Software\Microsoft\ServerManager /V DoNotOpenServerManagerAtLogon /t REG_DWORD /D 00000001 /f
cmd /c netsh advfirewall firewall delete rule name=all dir=out
