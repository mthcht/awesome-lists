rule TrojanDownloader_Win32_Sinowal_A_2147630077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinowal.A"
        threat_id = "2147630077"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c9 92 07 00 00 83 f1 50 [0-16] c1 f9 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 02 88 45 fb [0-16] 8a 55 fb 88 11 8b 45 ?? 05 ?? ?? ?? ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Sinowal_A_2147630077_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinowal.A"
        threat_id = "2147630077"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c9 92 07 00 00 83 f1 50 [0-16] c1 f9 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 02 88 45 fb [0-16] 8a 55 fb 88 11 8b 45 ?? 83 c0 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Sinowal_A_2147630077_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinowal.A"
        threat_id = "2147630077"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1f 8b 55 ?? 03 55 ?? 0f be 02 83 c0 ?? 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 83 c2 01 89 55 ?? eb d4}  //weight: 1, accuracy: Low
        $x_1_2 = {75 09 c7 45 fc fe ff ff ff eb 71 68 ?? ?? ?? ?? 8b 4d ?? 51 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 38}  //weight: 1, accuracy: Low
        $x_1_3 = {e9 34 01 00 00 0f b7 45 14 3d bb 01 00 00 75 0c 8b 4d f8 81 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Sinowal_B_2147633927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinowal.B"
        threat_id = "2147633927"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 65 76 65 72 66 69 6c 65 00 72 65 76 65 6e 65 6c 69 66}  //weight: 1, accuracy: High
        $x_1_2 = {83 79 58 05 0f 83}  //weight: 1, accuracy: High
        $x_1_3 = {81 c9 00 07 00 00 83 f1 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Sinowal_E_2147653473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinowal.E"
        threat_id = "2147653473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 79 58 05 0f 83}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 83 c0 01 50 8f 45 fc}  //weight: 1, accuracy: High
        $x_1_3 = {8f 45 f5 50 8f 45 f9 66 89 45 fd 55 2b eb 8b eb 5d 3b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

