# WDControl

WDControl is a GUI and commandline utility to disable or remove Windows Defender. Below are my notes and findings. 

20211231_WDControl_1.5.0.exe is a compiled AutoIt executable. I used the [Reverse Engineer's Toolkit](https://github.com/mentebinaria/retoolkit) that includes two AutoIt decompilers to decompile the AutoIt script. Unfortunately, the autoit code is obfouscated. More information about decompiling AutoIt scripts can be found here: [Decompile AutoIt executables](https://github.com/V1V1/OffensiveAutoIt#decompiling-autoit-executables)

The WDControl utility, once launched geneates an executable in the users temp folder called [WDC_nsudo.exe](https://github.com/M2Team/NSudo)

## Defender detections

'NSudo' hacktool was prevented
'Tnega' malware was detected
'Tnega' malware was prevented
'NSudo' malware was detected during lateral movement
'Tnega' malware was detected during lateral movement
An active 'Nsudo' hacktool in a command line was prevented from executing
An active 'Tnega' malware process was detected while executing
An active 'Tnega' malware process was detected while executing and terminated
An active 'Tnega' malware was blocked
Anomaly detected in ASEP registry
Privilege escalation using token duplication
Security software was disabled
Suspicious System Owner/User Discovery

## Mitre Att&ck

| Tactic              | Technique                                      | Alert Title                                  |
|---------------------|------------------------------------------------|----------------------------------------------|
| DefenseEvasion      | Disable or Modify Tools (T1562.001)            | Security software was disabled               |
| Discovery           | System Owner/User Discovery (T1033)            | Suspicious System Owner/User Discovery       |
| Discovery           | Permission Groups Discovery (T1069)            | Suspicious System Owner/User Discovery       |
| Discovery           | Account Discovery (T1087)                      | Suspicious System Owner/User Discovery       |
| Discovery           | Local Account (T1087.001)                      | Suspicious System Owner/User Discovery       |
| Discovery           | Domain Account (T1087.002)                     | Suspicious System Owner/User Discovery       |
| Persistence         | Modify Registry (T1112)                        | Anomaly detected in ASEP registry            |
| Persistence         | Registry Run Keys / Startup Folder (T1547.001) | Anomaly detected in ASEP registry            |
| Persistence         | Create Account (T1136)                         | local account created                        |
| PrivilegeEscalation | Exploitation for Privilege Escalation (T1068)  | Privilege escalation using token duplication |
| PrivilegeEscalation | Access Token Manipulation (T1134)              | Privilege escalation using token duplication |

## 20211231_WDControl_1.5.0.exe

Author: https://whatk.me/wdcontrol
GitHub: https://github.com/lhzptg/WDControl
VirusTotal: https://www.virustotal.com/gui/file/09e309bc1e77032dac37a07e55c89c24ce46fb263fa2f05c17ae2c3e6e89a4d4

ThreatName: Trojan:Win32/Tnega!MSR
SHA1: cb4a2858f6cbfe9042ce2f50d223faff7973859a
SHA256: 09e309bc1e77032dac37a07e55c89c24ce46fb263fa2f05c17ae2c3e6e89a4d4
MD5: 6262e139bedf460c6593e38260b5f455

## Commands executed

cmd.exe /c whoami
cmd.exe /c net stop WinDefend
cmd.exe /c net stop WdNisSvc
cmd.exe /c net stop WdNisDrv
cmd.exe /c net stop WdFilter
cmd.exe /c net stop WdBoot


## Registry Keys touched

| RegistryKey                                                                   | RegistryValueName  | RegistryValueData                             |
|-------------------------------------------------------------------------------|--------------------|-----------------------------------------------|
| HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP         |                    | {09A47860-11B0-4DA5-AFA5-26D86198A780}        |
| HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP |                    | {09A47860-11B0-4DA5-AFA5-26D86198A780}        |
| HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP     |                    | {09A47860-11B0-4DA5-AFA5-26D86198A780}        |
| HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender                        | DisableAntiSpyware | 1                                             |
| HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features               | TamperProtection   | 0                                             |
| HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run              | SecurityHealth     | C:\Windows\system32\SecurityHealthSystray.exe |
| HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender               | DisableAntiSpyware | 1                                             |
| HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend                    | Start              | 3                                             |



## WDC_Nsudo.exe / nsudo.exe

Author: https://nsudo.m2team.org/en-us/
GitHub: https://github.com/M2Team/NSudo
VirusTotal: https://www.virustotal.com/gui/file/f9a15143ea9724235e6bd3a025d6ed3c5dd2a47bcf09ee9eca691388750d44a4


ThreatName: HackTool:Win32/NSudo.A
SHA1: 58f94d4d8bed4e492b49f16438f71e52658dbb4b
SHA256: f9a15143ea9724235e6bd3a025d6ed3c5dd2a47bcf09ee9eca691388750d44a4
MD5: e379ae2bc3efc0737f764067ea262210

## Commands executed

WDC_Nsudo.exe -U:T -P:E -Wait -Priority:High C:\Temp\wd\20211231_WDControl_1.5.0.exe /disable




