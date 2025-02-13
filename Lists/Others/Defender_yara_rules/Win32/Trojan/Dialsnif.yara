rule Trojan_Win32_Dialsnif_A_2147573898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialsnif.gen!A"
        threat_id = "2147573898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 db b8 6f 00 00 00 30 44 1d 00 80 7c 1d 00 09 74 0e 05 93 00 00 00 43 81 fb 00 10 00 00 7c e7 89 fb 81 c3 00 04 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {85 c0 74 0e c6 00 00 48 80 38 20 74 05 c6 00 00 eb f5 8b 44 24 04 6a 00 50 56 e8}  //weight: 3, accuracy: High
        $x_3_3 = {55 8b 6c 24 10 8b 5c 24 0c 8b 54 24 08 43 8a 44 1d 00 84 c0 74 06 88 02 42 43 eb f2 43 88 02 89 d8 5d c2 0c 00}  //weight: 3, accuracy: High
        $x_3_4 = {56 8b 74 24 08 31 db 31 c0 b9 10 00 00 00 8a 1e 46 80 eb 30 72 0b 80 fb 09 77 06 f7 e1 01 d8 eb ed 5e c2 04 00}  //weight: 3, accuracy: High
        $x_3_5 = {8b 4d fc 8b 5d 08 81 c3 3c 02 00 00 b8 9c 01 00 00 89 03 01 c3 e2 fa 8b 5d 08 81 c3 3c 02 00 00}  //weight: 3, accuracy: High
        $x_1_6 = "javascript:'<html><head><title>Members Area Access</title></head><body><big><center><br><br>Save the login and password generated for you. It will grant access for 7 days.<br><br>Your LOGIN is: <b>" ascii //weight: 1
        $x_1_7 = "</b><br>Your PASSWORD is: <b>" ascii //weight: 1
        $x_1_8 = "</b><br>Members Area URL: <a href=" ascii //weight: 1
        $x_1_9 = "</a><br><br>To access use your usual connection.</center></big></body></html>'" ascii //weight: 1
        $x_1_10 = "ATM0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dialsnif_B_2147573957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialsnif.gen!B"
        threat_id = "2147573957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 51 08 8a 08 80 f9 e8 75 0f 8b 48 01 8d 4c 19 05 2b c8 83 e9 05 89 48 01}  //weight: 3, accuracy: High
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "OpenProcessToken" ascii //weight: 1
        $x_1_4 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_5 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dialsnif_C_2147576979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialsnif.gen!C"
        threat_id = "2147576979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "49"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\close.log" ascii //weight: 1
        $x_1_2 = "\\dial.log" ascii //weight: 1
        $x_1_3 = "\\Shell\\Open" ascii //weight: 1
        $x_1_4 = "\\Shell\\Open\\Command" ascii //weight: 1
        $x_1_5 = "\\WinInit.Ini" ascii //weight: 1
        $x_1_6 = "DSBEAGLE-1111-1111-1111-111111111111" ascii //weight: 1
        $x_1_7 = "Control Panel\\International" ascii //weight: 1
        $x_1_8 = "DefaultInternet" ascii //weight: 1
        $x_1_9 = "trackkey.exe" ascii //weight: 1
        $x_1_10 = "trackurl.exe" ascii //weight: 1
        $x_1_11 = "kill.exe" ascii //weight: 1
        $x_1_12 = "dial.exe" ascii //weight: 1
        $x_1_13 = "dial://" ascii //weight: 1
        $x_1_14 = "direct.exe" ascii //weight: 1
        $x_1_15 = "http://www.adserver.com" ascii //weight: 1
        $x_1_16 = "http://www.alexa.com" ascii //weight: 1
        $x_1_17 = "http://www.alibaba.com" ascii //weight: 1
        $x_1_18 = "http://www.amazon.com" ascii //weight: 1
        $x_1_19 = "http://www.apple.com" ascii //weight: 1
        $x_1_20 = "http://www.cnn.com" ascii //weight: 1
        $x_1_21 = "http://www.ebay.com" ascii //weight: 1
        $x_1_22 = "http://www.fastclick.com" ascii //weight: 1
        $x_1_23 = "http://www.icq.com" ascii //weight: 1
        $x_1_24 = "http://www.lycos.com" ascii //weight: 1
        $x_1_25 = "http://www.mapquest.com" ascii //weight: 1
        $x_1_26 = "http://www.microsoft.com" ascii //weight: 1
        $x_1_27 = "http://www.mlb.com" ascii //weight: 1
        $x_1_28 = "http://www.monster.com" ascii //weight: 1
        $x_1_29 = "http://www.nba.com" ascii //weight: 1
        $x_1_30 = "http://www.netscape.com" ascii //weight: 1
        $x_1_31 = "http://www.nytimes.com" ascii //weight: 1
        $x_1_32 = "http://www.tripod.com" ascii //weight: 1
        $x_1_33 = "http://www.xanga.com" ascii //weight: 1
        $x_1_34 = "http://www.yahoo.com" ascii //weight: 1
        $x_1_35 = "Software\\Microsoft\\Internet Account Manager" ascii //weight: 1
        $x_1_36 = "Software\\Microsoft\\Internet Account Manager\\Accounts\\" ascii //weight: 1
        $x_1_37 = "Software\\Microsoft\\Internet Explorer" ascii //weight: 1
        $x_1_38 = "Software\\Microsoft\\RAS AutoDial\\Default" ascii //weight: 1
        $x_1_39 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_40 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" ascii //weight: 1
        $x_1_41 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_42 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii //weight: 1
        $x_1_43 = "Software\\Microsoft\\WinNT\\CurrentVersion" ascii //weight: 1
        $x_1_44 = "CreateThread" ascii //weight: 1
        $x_1_45 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_46 = "EnumProcesses" ascii //weight: 1
        $x_1_47 = "EnumProcessModules" ascii //weight: 1
        $x_1_48 = "Module32First" ascii //weight: 1
        $x_1_49 = "Module32Next" ascii //weight: 1
        $x_1_50 = "OpenProcess" ascii //weight: 1
        $x_1_51 = "RasEnumDevicesA" ascii //weight: 1
        $x_1_52 = "RasGetEntryDialParamsA" ascii //weight: 1
        $x_1_53 = "RasGetEntryPropertiesA" ascii //weight: 1
        $x_1_54 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_55 = "RemoveDirectoryA" ascii //weight: 1
        $x_1_56 = "ResumeThread" ascii //weight: 1
        $x_1_57 = "ShellExecuteA" ascii //weight: 1
        $x_1_58 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (49 of ($x*))
}

