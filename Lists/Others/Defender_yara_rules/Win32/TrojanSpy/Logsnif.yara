rule TrojanSpy_Win32_Logsnif_2147573858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Logsnif"
        threat_id = "2147573858"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {80 78 01 00 74 07 80 38 00 74 fb eb ed fe 40 01 53 56 57 50 8c da 64 8b 0d 30 00 00 00 f6 c2 04 be}  //weight: 3, accuracy: High
        $x_3_2 = {75 73 ba 6c 02 fe 7f 8a 22 80 fc 04 8a 42 04 72 05 80 fc 05 76 04 66 b8 33 03 c1 e0 10 66 b8 00 01 ab 8b 51 0c 8b 42 1c 8b 58 08 b8}  //weight: 3, accuracy: High
        $x_3_3 = {66 b8 0a 84 bb 00 00 f7 bf 80 fa 60 73 02 b0 03 ba}  //weight: 3, accuracy: High
        $x_1_4 = "Outlook Express\\msimn.exe" ascii //weight: 1
        $x_1_5 = "Radim Picha" ascii //weight: 1
        $x_1_6 = "ProgramFilesDir" ascii //weight: 1
        $x_1_7 = "EliRT" ascii //weight: 1
        $x_1_8 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_9 = "E8PiRzJmoCs7hH30lPrj" ascii //weight: 1
        $x_1_10 = "Software\\Adobe\\SUBG" ascii //weight: 1
        $x_1_11 = "NtOpenThread" ascii //weight: 1
        $x_1_12 = "ReadProcessMemory" ascii //weight: 1
        $x_1_13 = "SetThreadAffinityMask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Logsnif_A_2147593635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Logsnif.gen!A"
        threat_id = "2147593635"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_150_1 = "STUPID KAV" ascii //weight: 150
        $x_25_2 = "c:\\me.mp3" ascii //weight: 25
        $x_25_3 = "C:\\ali.html" ascii //weight: 25
        $x_5_4 = "AntiSpyware" ascii //weight: 5
        $x_5_5 = "AntiSpyware.exe" ascii //weight: 5
        $x_5_6 = "spywaredoctor.dll" ascii //weight: 5
        $x_5_7 = "System32\\drivers\\ssl" ascii //weight: 5
        $x_5_8 = "System32\\drivers\\ssl\\06" ascii //weight: 5
        $x_1_9 = "madTools" ascii //weight: 1
        $x_1_10 = "madDisAsm" ascii //weight: 1
        $x_1_11 = "C:\\WINDOWS\\spywaredoctor.dll" ascii //weight: 1
        $x_1_12 = "C:\\WINDOWS\\System32\\drivers\\ssl" ascii //weight: 1
        $x_1_13 = "C:\\WINDOWS\\System32\\drivers\\ssl\\06" ascii //weight: 1
        $x_1_14 = "VirtualAllocEx" ascii //weight: 1
        $x_1_15 = "FindExecutableA" ascii //weight: 1
        $x_1_16 = "ReadProcessMemory" ascii //weight: 1
        $x_1_17 = "WriteProcessMemory" ascii //weight: 1
        $x_1_18 = "CreateRemoteThread" ascii //weight: 1
        $x_1_19 = "NtOpenSection" ascii //weight: 1
        $x_1_20 = "NtMapViewOfSection" ascii //weight: 1
        $x_1_21 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_22 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_23 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_150_*) and 1 of ($x_25_*) and 4 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_150_*) and 1 of ($x_25_*) and 5 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_150_*) and 2 of ($x_25_*) and 10 of ($x_1_*))) or
            ((1 of ($x_150_*) and 2 of ($x_25_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_150_*) and 2 of ($x_25_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Logsnif_D_2147593803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Logsnif.gen!D"
        threat_id = "2147593803"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "225"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_50_2 = "RavMonHelp" ascii //weight: 50
        $x_50_3 = "soul.exe" ascii //weight: 50
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_5_6 = "ReadProcessMemory" ascii //weight: 5
        $x_5_7 = "WriteProcessMemory" ascii //weight: 5
        $x_5_8 = "InternetReadFile" ascii //weight: 5
        $x_1_9 = "InternetOpenA" ascii //weight: 1
        $x_1_10 = "InternetConnectA" ascii //weight: 1
        $x_1_11 = "HttpSendRequestA" ascii //weight: 1
        $x_1_12 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_13 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_14 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_15 = "avpcc." ascii //weight: 1
        $x_1_16 = "_avpm." ascii //weight: 1
        $x_1_17 = "avp32." ascii //weight: 1
        $x_1_18 = "antivirus." ascii //weight: 1
        $x_1_19 = "fsav.exe" ascii //weight: 1
        $x_1_20 = "norton." ascii //weight: 1
        $x_1_21 = "msmpeng." ascii //weight: 1
        $x_1_22 = "msmpsvc." ascii //weight: 1
        $x_1_23 = "2.0.0.1" ascii //weight: 1
        $x_1_24 = "&servers=" ascii //weight: 1
        $x_1_25 = "&username=" ascii //weight: 1
        $x_1_26 = "&password=" ascii //weight: 1
        $x_1_27 = "&rwmc=" ascii //weight: 1
        $x_1_28 = "&passlock=" ascii //weight: 1
        $x_1_29 = "mail.asp" ascii //weight: 1
        $x_1_30 = "Send OK!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_5_*) and 20 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 3 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Logsnif_E_2147593826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Logsnif.gen!E"
        threat_id = "2147593826"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "125"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Ring0Port.sys" ascii //weight: 100
        $x_1_2 = "ping.exe" ascii //weight: 1
        $x_1_3 = "lsass.exe" ascii //weight: 1
        $x_1_4 = "svchost.exe" ascii //weight: 1
        $x_1_5 = "slil.ru" ascii //weight: 1
        $x_1_6 = ":\\Program Files\\Common Files\\moatumonn.exe" ascii //weight: 1
        $x_1_7 = ":\\Program Files\\Internet Explorer\\Iexplore.exe" ascii //weight: 1
        $x_1_8 = ":\\Program Files\\opera\\opera.exe" ascii //weight: 1
        $x_1_9 = ":\\Program Files\\Outlook Express\\msimn.exe" ascii //weight: 1
        $x_1_10 = "\\system32\\drivers\\svchost.exe" ascii //weight: 1
        $x_1_11 = "system\\CurrentControlSet\\Services" ascii //weight: 1
        $x_3_12 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 3
        $x_1_13 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_14 = "OutpostMainWindowClass" ascii //weight: 1
        $x_1_15 = "Outpost Firewall Pro" ascii //weight: 1
        $x_1_16 = "Kaspersky Anti-Hacker" ascii //weight: 1
        $x_1_17 = "JeticoPersonalFirewall" ascii //weight: 1
        $x_1_18 = "Activity Monitor" ascii //weight: 1
        $x_1_19 = "MmGetPhysicalAddress" ascii //weight: 1
        $x_1_20 = "MmIsAddressValid" ascii //weight: 1
        $x_5_21 = "IoGetCurrentProcess" ascii //weight: 5
        $x_1_22 = "Ke386SetIoAccessMap" ascii //weight: 1
        $x_2_23 = "Ke386QueryIoAccessMap" ascii //weight: 2
        $x_5_24 = "WriteProcessMemory" ascii //weight: 5
        $x_1_25 = "ZwOpenSection" ascii //weight: 1
        $x_1_26 = "ZwLoadDriver" ascii //weight: 1
        $x_1_27 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_2_28 = "OpenSCManagerA" ascii //weight: 2
        $x_1_29 = "socket" ascii //weight: 1
        $x_3_30 = "WSAStartup" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 22 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 19 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 20 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Logsnif_F_2147599749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Logsnif.gen!F"
        threat_id = "2147599749"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 7a 61 72 64 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 5c 57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 [0-32] 49 6e 73 74 61 6c 6c 50 61 74 68 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 47 78 57 69 6e 64 6f 77 43 00}  //weight: 1, accuracy: High
        $x_3_3 = {00 00 3d 0d 1c 00 00 7f 2c 0f 84}  //weight: 3, accuracy: High
        $x_3_4 = {75 2f 83 7e 04 4b 75 19 6a 00}  //weight: 3, accuracy: High
        $x_3_5 = {50 c1 ee 10 81 e6 ff 00 00 00 56 53}  //weight: 3, accuracy: High
        $x_10_6 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_7 = "GetKeyboardState" ascii //weight: 10
        $x_10_8 = "GetForegroundWindow" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Logsnif_FH_2147611021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Logsnif.FH"
        threat_id = "2147611021"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 79 ff 69 ff ?? ?? 00 00 66 31 7c 4a fe 66 8b 3c 4a 66 01 7c 4a fe e2 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 90 90 90 90 90 90 ff d0 ff 56 04 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

