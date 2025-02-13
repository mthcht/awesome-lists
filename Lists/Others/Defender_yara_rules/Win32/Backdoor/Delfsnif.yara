rule Backdoor_Win32_Delfsnif_B_2147582899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delfsnif.gen!B"
        threat_id = "2147582899"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "305"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8b d8 8b 43 3c 03 c3 83 c0 04 83 c0 14 8b 70 60 03 f3 8b 6e 18 4d 85 ed 72 41 45 33 ff 8b 46 20 03 c3 8b d7 c1 e2 02 03 c2 8b 00 03 c3 8b 14 24 e8 ?? ?? ?? ?? 85 c0 75 1e 8b 46 24 03 c3 8b d7 03 d2 03 c2 0f b7 00 c1 e0 02 8b 56 1c 03 d3 03 c2 8b 00 03 c3 eb 06 47 4d 75 c2}  //weight: 100, accuracy: Low
        $x_100_2 = "%s\\netsh.exe firewall add allowedprogram" ascii //weight: 100
        $x_10_3 = "LcShield" ascii //weight: 10
        $x_10_4 = "vinvnc4" ascii //weight: 10
        $x_10_5 = "Sfmantec Antipirus" ascii //weight: 10
        $x_10_6 = "Rav_onClass" ascii //weight: 10
        $x_10_7 = "TfLockDownMain" ascii //weight: 10
        $x_10_8 = "ZAGrameWnd" ascii //weight: 10
        $x_10_9 = "TMalwareItem" ascii //weight: 10
        $x_10_10 = "http://%s:%d/%s" ascii //weight: 10
        $x_10_11 = "\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_12 = "software\\microsoft\\windows\\currentversion" ascii //weight: 10
        $x_1_13 = "GetNetworkParams" ascii //weight: 1
        $x_1_14 = "IcmpSendEcho" ascii //weight: 1
        $x_1_15 = "WSARecv" ascii //weight: 1
        $x_1_16 = "WSASend" ascii //weight: 1
        $x_1_17 = "WSAConnect" ascii //weight: 1
        $x_1_18 = "NtCreateFile" ascii //weight: 1
        $x_1_19 = "DEVICE\\TCP" ascii //weight: 1
        $x_1_20 = "NtProtectVirtualMemory" ascii //weight: 1
        $x_1_21 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_22 = "ReadProcessMemory" ascii //weight: 1
        $x_1_23 = "OpenProcess" ascii //weight: 1
        $x_1_24 = "OpenProcessToken" ascii //weight: 1
        $x_1_25 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_26 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 10 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delfsnif_D_2147583427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delfsnif.gen!D"
        threat_id = "2147583427"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "pixcher bot v 1.1 builder" ascii //weight: 20
        $x_10_2 = "Enter http url to index.php of botadmin panel:" ascii //weight: 10
        $x_10_3 = "Enter name of exe file:" ascii //weight: 10
        $x_5_4 = "compiled..." ascii //weight: 5
        $x_5_5 = "packing..." ascii //weight: 5
        $x_5_6 = "http://test.ru/botadmin/index.php" ascii //weight: 5
        $x_5_7 = "build.dat" ascii //weight: 5
        $x_5_8 = "upx.exe" ascii //weight: 5
        $x_5_9 = "WinExec" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_5_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delfsnif_C_2147583507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delfsnif.gen!C"
        threat_id = "2147583507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "hacked by Khaled" ascii //weight: 10
        $x_10_2 = "KhaloBot v 1.0" ascii //weight: 10
        $x_10_3 = "*Backdoor %s by Khaled (c) 2005*" ascii //weight: 10
        $x_1_4 = "xxtype.cpp" ascii //weight: 1
        $x_1_5 = "client.exe" ascii //weight: 1
        $x_1_6 = "type =-info-= to get victims computername" ascii //weight: 1
        $x_1_7 = "type =-opencd-= to open victims cd rom" ascii //weight: 1
        $x_1_8 = "type =-bomb-= to bomb victim with notepad" ascii //weight: 1
        $x_1_9 = "type =-restart-= to restart victims machine" ascii //weight: 1
        $x_1_10 = "type =-url-= to start www.fuck.com" ascii //weight: 1
        $x_1_11 = "type =-down-= to shutdown remote machine" ascii //weight: 1
        $x_1_12 = "type =-label-= to rename label to %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delfsnif_E_2147583508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delfsnif.gen!E"
        threat_id = "2147583508"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "troi.exe" ascii //weight: 20
        $x_20_2 = "svchost.exe" ascii //weight: 20
        $x_20_3 = "Explorer.exe " ascii //weight: 20
        $x_20_4 = "argentus.exe" ascii //weight: 20
        $x_20_5 = "WinProtect" ascii //weight: 20
        $x_5_6 = "getexe" ascii //weight: 5
        $x_5_7 = "sendpass" ascii //weight: 5
        $x_5_8 = "WriteProcessMemory" ascii //weight: 5
        $x_5_9 = "InternetReadFile" ascii //weight: 5
        $x_5_10 = "InternetOpen" ascii //weight: 5
        $x_5_11 = "VirtualAllocEx" ascii //weight: 5
        $x_1_12 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows XP 5.1)" ascii //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $n_100_14 = "AnVir Task Manager" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_20_*) and 4 of ($x_5_*))) or
            ((4 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delfsnif_F_2147593033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delfsnif.gen!F"
        threat_id = "2147593033"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "425"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "rpcs.exe" wide //weight: 100
        $x_100_2 = "Generic Host Process for Win32 Services" wide //weight: 100
        $x_50_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 50
        $x_50_4 = "FGIntRSA" ascii //weight: 50
        $x_25_5 = "FHideProcess" ascii //weight: 25
        $x_25_6 = "vHideProcess" ascii //weight: 25
        $x_25_7 = "WriteProcessMemory" ascii //weight: 25
        $x_25_8 = "Toolhelp32ReadProcessMemory" ascii //weight: 25
        $x_10_9 = "delmedll.bat" ascii //weight: 10
        $x_10_10 = "delmeexe.bat" ascii //weight: 10
        $x_10_11 = "del .\\delmedll.bat" ascii //weight: 10
        $x_10_12 = "cmd.exe" ascii //weight: 10
        $x_10_13 = "Internet Explorer" ascii //weight: 10
        $x_10_14 = "OpenProcessToken" ascii //weight: 10
        $x_10_15 = "AdjustTokenPrivileges" ascii //weight: 10
        $x_10_16 = "WinExec" ascii //weight: 10
        $x_10_17 = "SeShutdownPrivilege" ascii //weight: 10
        $x_10_18 = "LookupPrivilegeValueA" ascii //weight: 10
        $x_10_19 = "Winsock2Flood" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_25_*) and 10 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 4 of ($x_25_*) and 8 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_25_*) and 10 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_25_*) and 8 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 3 of ($x_25_*) and 5 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 4 of ($x_25_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delfsnif_B_2147602207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delfsnif.B"
        threat_id = "2147602207"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "342"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SeDebugPrivilege" ascii //weight: 100
        $x_100_2 = "WriteProcessMemory" ascii //weight: 100
        $x_100_3 = "ZwQuerySystemInformation" ascii //weight: 100
        $x_10_4 = "del .\\delmedll.bat" ascii //weight: 10
        $x_10_5 = "delmeexe.bat goto loop" ascii //weight: 10
        $x_10_6 = "\\Device\\PhysicalMemory" wide //weight: 10
        $x_10_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_8 = "kljspass:" ascii //weight: 1
        $x_1_9 = "menameexe:" ascii //weight: 1
        $x_1_10 = "menamedll:" ascii //weight: 1
        $x_1_11 = "exefile:" ascii //weight: 1
        $x_1_12 = "dllfile:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

