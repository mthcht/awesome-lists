rule Trojan_Win32_Poison_RPS_2147835817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poison.RPS!MTB"
        threat_id = "2147835817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d d0 83 c1 01 89 4d d0 83 7d d0 0d 73 17 8b 55 d0 33 c0 8a 44 15 e0 35 cc 00 00 00 8b 4d d0 88 44 0d e0 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Poison_EM_2147850225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poison.EM!MTB"
        threat_id = "2147850225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EZEL\\newsletter\\VB6" ascii //weight: 1
        $x_1_2 = "Hiccupp2" ascii //weight: 1
        $x_1_3 = "frump6" ascii //weight: 1
        $x_1_4 = "nslt.pdf" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Poison_NA_2147928891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poison.NA!MTB"
        threat_id = "2147928891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0}  //weight: 2, accuracy: High
        $x_1_2 = {4e 81 ce 00 ff ff ff 46 8a 17 8b 44 b4 14 88 54 24 10 89 07 8b 54 24 10 83 c7 04 81 e2 ff 00 00 00 41 81 f9 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_4 = "\\explorer.exe" ascii //weight: 1
        $x_1_5 = "Outlook\\Profiles\\Outlook" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "encryptedPassword" ascii //weight: 1
        $x_1_8 = "logins.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Poison_NB_2147928892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poison.NB!MTB"
        threat_id = "2147928892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0}  //weight: 2, accuracy: High
        $x_1_2 = {4e 81 ce 00 ff ff ff 46 8a 17 8b 44 b4 14 88 54 24 10 89 07 8b 54 24 10 83 c7 04 81 e2 ff 00 00 00 41 81 f9 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "m_Stub" ascii //weight: 1
        $x_1_4 = "explorer.exe" ascii //weight: 1
        $x_1_5 = "C:\\file.exe" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
        $x_1_8 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

