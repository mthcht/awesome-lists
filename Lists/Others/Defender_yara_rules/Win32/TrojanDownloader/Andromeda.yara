rule TrojanDownloader_Win32_Andromeda_SIB_2147787692_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Andromeda.SIB!MTB"
        threat_id = "2147787692"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 ?? 0f be 08 89 4d ?? 8b 55 08 03 55 00 8b 45 08 03 45 ?? 8a 08 88 0a 8b 55 08 03 55 03 8a 45 01 88 02 8b 45 00 83 c0 ?? 89 45 00 8b 4d 03 83 e9 ?? 89 4d 03 8b 55 00 3b 55 03 7d 29}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 0f be 02 85 c0 74 ?? 8b 4d 08 8a 11 80 c2 ?? 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 11 33 55 ?? 03 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 88 10 8b 55 03 83 c2 01 89 55 03 8b 45 03 3b 05 ?? ?? ?? ?? 73 ?? 8b 0d 02 03 4d 03 0f b6 11 33 55 00 03 55 01 a1 02 03 45 03 88 10 eb ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Andromeda_SIBB_2147787693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Andromeda.SIBB!MTB"
        threat_id = "2147787693"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 56 53 ff d7 53 68 ?? ?? ?? ?? 56 50 ff 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 55 ?? a1 02 8a 08 [0-128] 0f b6 c9 83 f1 ?? [0-128] 33 f6 39 35 00 76 ?? a1 02 8a 14 30 32 d1 80 c2 ?? 88 14 30 46 3b 35 00 72 ?? [0-128] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Andromeda_SIBC_2147788241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Andromeda.SIBC!MTB"
        threat_id = "2147788241"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 56 57 ff 15 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6a ?? 57 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 f8 ff 74 ?? 57 68 ?? ?? ?? ?? 56 ff 35 06 50 ff 15 ?? ?? ?? ?? a1 06 0f b6 08 83 f1 ?? 33 f6 39 3d 0a 76 ?? 8a 14 30 32 d1 80 c2 ?? 88 14 30 46 3b 35 0a 72 ec ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Andromeda_SIBD_2147788242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Andromeda.SIBD!MTB"
        threat_id = "2147788242"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 50 6a 00 ff 55 ?? a3 ?? ?? ?? ?? [0-176] 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 01 ff 35 ?? ?? ?? ?? ff 55 ?? a1 01 8a 00 88 45 ?? [0-176] 0f b6 45 09 8b 35 01 33 c9 83 f0 ?? 39 0d 03 76 ?? 8a 14 0e 32 d0 80 c2 ?? 88 14 0e 41 3b 0d 03 72 ?? ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Andromeda_SIBE_2147788243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Andromeda.SIBE!MTB"
        threat_id = "2147788243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 56 68 ?? ?? ?? ?? 6a ?? 56 6a ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 5f 83 f8 ff 74 ?? 56 68 ?? ?? ?? ?? 53 ff 35 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a1 08 0f b6 08 83 f1 ?? 39 35 07 76 ?? 8a 14 30 32 d1 80 c2 ?? 88 14 30 46 3b 35 07 72 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

