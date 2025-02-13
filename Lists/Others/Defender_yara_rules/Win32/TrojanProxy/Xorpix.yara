rule TrojanProxy_Win32_Xorpix_A_2147576648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Xorpix.gen!A"
        threat_id = "2147576648"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorpix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%swork.php?method=update&id=%s" ascii //weight: 2
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_3 = "%swork.php?method=get&port=%lu&id=%lu&type=%lu&winver=%s" ascii //weight: 2
        $x_1_4 = "main_bt" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "socket" ascii //weight: 1
        $x_1_7 = "inet_addr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Xorpix_B_2147576649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Xorpix.gen!B"
        threat_id = "2147576649"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorpix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Upack" ascii //weight: 3
        $x_2_2 = {55 8b ec 81 c4 fc fe ff ff 57 56 53}  //weight: 2, accuracy: High
        $x_2_3 = {85 c0 8b fe be ff ff ff ff 8d 3d}  //weight: 2, accuracy: High
        $x_2_4 = {8d bd fc fe ff ff b9 04 01 00 00}  //weight: 2, accuracy: High
        $x_6_5 = {8b ec 81 c4 fc fe ff ff 8d 05 ?? 13 40 00 e8 ?? ?? 00 00 50 8d 85 fc fe ff ff 50 68 04 01 00 00 e8 ?? ?? 00 00 [0-3] e8 ?? ?? 00 00 59 33 c1 [0-3] 8b d0 ff 75 08 52 8d 15 ?? ?? 40 00 52 87 d2 8d 95}  //weight: 6, accuracy: Low
        $x_6_6 = {55 8b ec 56 57 53 8b 45 08 [0-2] 8b f8 [0-3] 8b 75 10 [0-2] 8b df [0-3] 87 d2 [0-2] 03 5d 0c [0-2] 8a 06 [0-5] 86 c0 30 27 [0-3] 83 c7 01 [0-3] 46 [0-3] 3b fb 74}  //weight: 6, accuracy: Low
        $x_1_7 = "GetTickCount" ascii //weight: 1
        $x_1_8 = "GetTempPathA" ascii //weight: 1
        $x_1_9 = "AddAtomA" ascii //weight: 1
        $x_1_10 = "FindFirstFileA" ascii //weight: 1
        $x_1_11 = "FindResourceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_6_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Xorpix_E_2147600522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Xorpix.gen!E"
        threat_id = "2147600522"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorpix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 5d 0c 8a 06 eb ?? [0-2] 30 07 90 47 46 3b fb 74 0d 8a 06 84 c0 75 f1 8b 75 10 8a 06 eb ea}  //weight: 1, accuracy: Low
        $x_1_2 = {64 6c 6c 2e 64 6c 6c 00 70 72 6f 63 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Xorpix_G_2147611347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Xorpix.G"
        threat_id = "2147611347"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorpix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 85 ff fb ff ff 68 01 04 00 00 50 e8 ?? ?? ff ff 8b 45 08 ff 30 5f 8d b5 ff fb ff ff}  //weight: 2, accuracy: Low
        $x_5_2 = {60 8b 45 08 89 45 fc 8d 45 fc 68 ?? ?? ?? 10 6a 00 50 68 ?? ?? ?? 10 6a 00 6a 00 e8 ?? ?? ?? 00 6a 19 e8 ?? ?? ?? 00 8b 45 08 39 45 fc 74 f1 61 ff 75 fc}  //weight: 5, accuracy: Low
        $x_2_3 = {32 0f 32 1f eb 03 80 e9 20 80 f9 20 73 f8 d3 c3 47 8a 17 0a d2 75 e9 81 f3}  //weight: 2, accuracy: High
        $x_2_4 = {89 45 fc 68 e1 03 00 00 ff 75 fc 68 ?? ?? 00 10 e8 ?? ?? 00 00 b8 00 00 00 00 8b 7d fc 8a 07 6a 01 50 68 e0 03 00 00 ff 75 fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Xorpix_D_2147803861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Xorpix.gen!D"
        threat_id = "2147803861"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorpix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "808"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {55 8b ec 56 57 53 8b 7d 08 [0-2] 8b 75 10 8b df 03 5d 0c 8a 06 eb ?? [0-2] 30 07 90 47 46 3b fb 74 0d 8a 06 84 c0 75 f1 8b 75 10 8a 06 eb ea 5b 5f 5e c9 c2 0c 00}  //weight: 100, accuracy: Low
        $x_100_2 = {e8 00 00 00 00 58 05 0c 00 00 00 50 e9}  //weight: 100, accuracy: High
        $x_100_3 = {89 85 d8 fe ff ff [0-16] c6 85 de fe ff ff 68 [0-16] 8b 85 d8 fe ff ff [0-16] 83 c0 1e [0-16] 89 85 df fe ff ff [0-16] 66 c7 85 e3 fe ff ff ff 15 [0-16] 8b 85 d8 fe ff ff [0-16] 83 c0 16 [0-16] 89 85 e5 fe ff ff [0-16] c6 85 e9 fe ff ff 68 [0-16] c7 85 ea fe ff ff 00 00 00 00 [0-16] 66 c7 85 ee fe ff ff ff 15 [0-16] 8b 85 d8 fe ff ff [0-16] 83 c0 1a [0-16] 89 85 f0 fe ff ff}  //weight: 100, accuracy: Low
        $x_300_4 = "desktop.ini" ascii //weight: 300
        $x_300_5 = {70 72 6f 63 31 00}  //weight: 300, accuracy: High
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "GetThreadContext" ascii //weight: 1
        $x_1_9 = "OpenProcess" ascii //weight: 1
        $x_1_10 = "Process32First" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
        $x_1_12 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_13 = "CreateRemoteThread" ascii //weight: 1
        $x_1_14 = "CreateProcessA" ascii //weight: 1
        $x_1_15 = "OpenSCManagerA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_300_*) and 2 of ($x_100_*) and 8 of ($x_1_*))) or
            ((2 of ($x_300_*) and 3 of ($x_100_*))) or
            (all of ($x*))
        )
}

