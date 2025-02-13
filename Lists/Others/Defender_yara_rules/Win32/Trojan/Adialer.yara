rule Trojan_Win32_Adialer_CQ_2147511013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.CQ"
        threat_id = "2147511013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run" ascii //weight: 10
        $x_10_2 = "modem" ascii //weight: 10
        $x_10_3 = "RASAPI32.DLL" ascii //weight: 10
        $x_10_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 [0-8] 33 32 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_5_5 = "@CS@instant" ascii //weight: 5
        $x_5_6 = "dialer0" ascii //weight: 5
        $x_1_7 = "0088193918008" ascii //weight: 1
        $x_1_8 = "008818399784" ascii //weight: 1
        $x_1_9 = "0088193911220" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_NAC_2147596917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.NAC"
        threat_id = "2147596917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Carlson" ascii //weight: 5
        $x_5_2 = "Carlson Dialer" ascii //weight: 5
        $x_5_3 = "http://prs.payperdownload.nl" ascii //weight: 5
        $x_5_4 = "RasEnumConnectionsA" ascii //weight: 5
        $x_5_5 = "InternetOpenUrlA" ascii //weight: 5
        $x_5_6 = "9B4AA442-9EBF-11D5-8C11-0050DA4957F5" ascii //weight: 5
        $x_1_7 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_8 = "&lasterror=" ascii //weight: 1
        $x_1_9 = "&linenumber=" ascii //weight: 1
        $x_1_10 = "realnumber" ascii //weight: 1
        $x_1_11 = "callrecords" ascii //weight: 1
        $x_1_12 = "http://prs.payperdownload.nl/radius/dialer_admin/geoip" ascii //weight: 1
        $x_1_13 = "angel@carlton" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_1_*))) or
            ((6 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_OR_2147600156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.OR"
        threat_id = "2147600156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 58 58 58 43 6c 61 73 73 00 00 00 00 4e 6f 74 20 63 6f 6e 6e 65 63 74 65 64 00 00 00 26 43 6f 6e}  //weight: 10, accuracy: High
        $x_10_2 = "www.areaxxx.biz" ascii //weight: 10
        $x_10_3 = "PER ENTRARE NELL'AREA ADULTI CLICCA su \"OK\" e poi su" ascii //weight: 10
        $x_1_4 = {4c 41 4e 00 58 58 58 00 33 36 36 30 32 32 32 00 45 52 52 4f 52 5f 42 55 46 46 45 52 5f 49 4e 56 41 4c 49 44 00 00 00 00 45 52 52 4f 52 5f 43 41 4e 4e 4f 54 5f 4f 50 45 4e 5f 50 48 4f 4e 45 42 4f 4f 4b}  //weight: 1, accuracy: High
        $x_1_5 = "RasDialA" ascii //weight: 1
        $x_1_6 = "RasEnumEntriesA" ascii //weight: 1
        $x_1_7 = "Processing modem callback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adialer_OS_2147601383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.OS"
        threat_id = "2147601383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_2 = "Ready to connect" ascii //weight: 1
        $x_1_3 = "rasdt_isdn" ascii //weight: 1
        $x_1_4 = "ERROR_CANNOT_OPEN_PHONEBOOK" ascii //weight: 1
        $x_1_5 = "RasDial" ascii //weight: 1
        $x_10_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 72 65 61 78 78 78 2e 62 69 7a 2f 69 76 72 2f 69 6e 64 65 78 ?? 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_10_7 = {b2 46 b3 54 80 bc 04 3c 4f 00 00 43 75 56 38 94 04 3d 4f 00 00 75 4d 80 bc 04 3e 4f 00 00 47 75 43 80 bc 04 3f 4f 00 00 5f 75 39 80 bc 04 40 4f 00 00 4f 75 2f 38 94 04 41 4f 00 00 75 26 38 94 04 42 4f 00 00 75 1d 80 bc 04 43 4f 00 00 53 75 13 80 bc 04 44 4f 00 00 45 75 09 38 9c 04 45 4f 00 00 74 07 40 3b c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_OU_2147603110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.OU"
        threat_id = "2147603110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 21 70 61 73 73 77 6f 72 64 [0-2] 21 7e 21 [0-32] 40 6f 63 65 61 6e}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 72 65 61 78 78 78 2e 62 69 7a 2f [0-16] 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_1_3 = ".lnk" ascii //weight: 1
        $x_1_4 = "ERROR_CANNOT_OPEN_PHONEBOOK" ascii //weight: 1
        $x_1_5 = "RasDialA" ascii //weight: 1
        $x_1_6 = "XXXClass" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_8 = "shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_LB_2147603714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.LB"
        threat_id = "2147603714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Application Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_3 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_5 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_6 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_7 = "ServiceDllUnloadOnStop" ascii //weight: 1
        $x_1_8 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_9 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_10 = "RasDialParams!%s#0" ascii //weight: 1
        $x_1_11 = "InternetReadFile" ascii //weight: 1
        $x_1_12 = "\\\\.\\RESSDTDOS" ascii //weight: 1
        $x_1_13 = "PhoneNumber" ascii //weight: 1
        $x_1_14 = "CVideoCap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adialer_CZ_2147605393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.CZ"
        threat_id = "2147605393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "219"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\ExeDialer1.exe" ascii //weight: 1
        $x_1_2 = "ExeStartFile" ascii //weight: 1
        $x_1_3 = "Software\\EGDHTML" ascii //weight: 1
        $x_1_4 = "FORCE_P2E" ascii //weight: 1
        $x_1_5 = "FORCE_DIALER" ascii //weight: 1
        $x_1_6 = "dialerexe.ini" ascii //weight: 1
        $x_1_7 = "NOCREDITCARD" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_9 = "_PROGRAMFILES_DIR_" ascii //weight: 1
        $x_1_10 = "_WINDOWS_DIR_" ascii //weight: 1
        $x_1_11 = "_SYSTEM_DIR_" ascii //weight: 1
        $x_1_12 = "login=" ascii //weight: 1
        $x_1_13 = "\\dialexe.epk" ascii //weight: 1
        $x_1_14 = "\\DesktopIcons" ascii //weight: 1
        $x_1_15 = "\\Instant Access" ascii //weight: 1
        $x_1_16 = "about:blank" ascii //weight: 1
        $x_1_17 = "\\offline.htm" ascii //weight: 1
        $x_1_18 = "Unable to load dialer" ascii //weight: 1
        $x_1_19 = "asked_billing_id" ascii //weight: 1
        $x_1_20 = "regsvr32.exe /s" ascii //weight: 1
        $x_100_21 = "instant access.exe" ascii //weight: 100
        $x_100_22 = {6a 01 5f 50 8d 45 ?? 50 56 56 56 56 56 8d 85 ?? ?? ff ff 56 50 56 89 7d ?? 66 89 ?? ?? ff 15 ?? ?? 40 00 85 c0 75 12 57 56 8d 85 ?? ?? ff ff 56 50 56 56 ff 15 ?? ?? 40 00 ff 75}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 19 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_BAF_2147627495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.BAF"
        threat_id = "2147627495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 6f 73 74 3a 20 [0-16] 2e 74 6f 6e 73 69 74 65 2e 62 69 7a}  //weight: 1, accuracy: Low
        $x_1_2 = "MPSockLib" ascii //weight: 1
        $x_1_3 = "/rp.php?a=" ascii //weight: 1
        $x_1_4 = "Validation en cours..." ascii //weight: 1
        $x_1_5 = "30 minutes de visio sexe " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adialer_OP_18051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.OP"
        threat_id = "18051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {89 5d f8 ad 8b d8 03 da ad 85 c0 74 3f 8b c8 83 e9 08 85 c9 74 ed 66 c7 45 fe ff ff 66 ad 66 83 7d fe ff 74 04}  //weight: 50, accuracy: High
        $x_50_2 = {8b 75 fc 8b 4d 0c 0f b6 36 c1 e1 08 0b ce c1 e0 08 ff 45 fc 89 4d 0c 8b 0c 93 8b f0 c1 ee 0b 0f af f1 39 75 0c 73 15 8b c6 be 00 08 00 00 2b f1 c1 ee 05 03 f1 89 34 93 03 d2 eb 16}  //weight: 50, accuracy: High
        $x_5_3 = {00 45 76 74 53 68 75 74 64 6f 77 6e 00 45 76 74 53 74 61 72 74 75 70 00 69 6e 73 74 00 72 75 6e 00 74 65 73 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 69 6e 73 74 00 69 6e 73 74 32 00 6d 6f 75 6e 74 00 73 74 61 72 74 75 70 00 74 65 73 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_OP_18051_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.OP"
        threat_id = "18051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "http://194.178.112.202" ascii //weight: 3
        $x_3_2 = "^jjf0%%'/*$'-.$''($(&(" ascii //weight: 3
        $x_1_3 = {73 61 74 5f 69 74 5f [0-15] 5f 30 5f 30 32 30 32 5f 30 30 30 37}  //weight: 1, accuracy: Low
        $x_1_4 = {38 39 32 5f 69 74 5f [0-15] 5f 30 5f 30 32 30 32 5f 30 30 30 37}  //weight: 1, accuracy: Low
        $x_1_5 = {31 37 38 5f 69 74 5f [0-15] 5f 30 5f 30 32 30 32 5f 30 30 30 37}  //weight: 1, accuracy: Low
        $x_1_6 = {31 30 33 33 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39) (30|2d|39)}  //weight: 1, accuracy: Low
        $x_1_7 = {38 39 32 32 31 31 ?? (30|2d|39) (30|2d|39)}  //weight: 1, accuracy: Low
        $x_1_8 = {38 39 39 30 32 30 ?? (30|2d|39) (30|2d|39)}  //weight: 1, accuracy: Low
        $x_1_9 = {31 37 38 32 30 37 32 30 (30|2d|39) (30|2d|39)}  //weight: 1, accuracy: Low
        $x_10_10 = "RasDialA" ascii //weight: 10
        $x_10_11 = "RasHangUpA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_OO_67528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer.OO"
        threat_id = "67528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://194.178.112.202" ascii //weight: 1
        $x_1_2 = {85 c0 75 27 56 55 57 e8 ?? ?? ?? ?? 83 3e 00 75 0a c7 05 ?? ?? ?? 00 01 00 00 00 68 ?? ?? ?? 00 ff d3 a1 ?? ?? 40 00 85 c0 74 d9}  //weight: 1, accuracy: Low
        $x_1_3 = {00 85 c0 74 d9 6a 24 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 c7 05 ?? ?? ?? ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 83 f8 07 75 11 c7 05 ?? ?? ?? ?? 01 00 00 00 bd 01 00 00 00 eb 21 a1 ?? ?? ?? 00 bd 01 00 00 00 48 a3 ?? ?? ?? 00 eb 0f 8b 06 50 e8 ?? ?? ?? ?? 68 d0 07 00 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_4 = {00 00 ff d3 83 3d ?? ?? ?? ?? 06 7c 06 89 ?? ?? ?? 40 00 8b 74 24 14 a1 ?? ?? ?? 00 83 c6 04 85 c0 89}  //weight: 1, accuracy: Low
        $x_1_5 = {74 24 14 0f 84 a8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adialer_83836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer"
        threat_id = "83836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 81 c4 5c ff ff ff ff 35 ad 47 40 00 e8 7a 07 00 00 68 a0 00 00 00 8d 85 5c ff ff ff 50 e8 fd 06 00 00 c7 85 5c ff ff ff a0 00 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 3b 07 00 00 83 f8 06 74 1e 68 e8 03 00 00 e8 de 06 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 1a 07 00 00 eb dd 68 90 01 00 00 e8 c0 06 00 00 c9 c3}  //weight: 10, accuracy: High
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "RasDialA" ascii //weight: 1
        $x_1_4 = "strstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adialer_83836_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer"
        threat_id = "83836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "modem" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "MZKERNEL32.DLL" ascii //weight: 1
        $x_1_4 = "mbp-r-agent" ascii //weight: 1
        $x_1_5 = "RasDialA" ascii //weight: 1
        $x_1_6 = "CreateMutex" ascii //weight: 1
        $x_1_7 = {55 8b ec b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 53 56 ?? ?? ?? 89 ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 45 08 68 ?? ?? ?? 00 ?? ?? a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 3d ?? ?? 00 00 ?? 0f 84 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

