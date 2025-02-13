rule TrojanDownloader_Win32_Neojit_A_2147654841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neojit.A"
        threat_id = "2147654841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neojit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 23 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {c7 40 4c 80 10 00 00 c7 40 50 7c 08 00 00 ba ?? ?? ?? ?? 89 50 54 eb ?? 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Neojit_A_2147654841_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neojit.A"
        threat_id = "2147654841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neojit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6e 65 77 67 2f 61 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 41 63 63 65 73 73 69 6e 67 20 74 68 65 20 73 65 72 76 65 72 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 55 70 64 61 74 65 20 61 70 70 20 2d 3e 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 6f 77 6e 6c 6f 61 64 20 75 72 6c 20 3d 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Neojit_A_2147654841_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neojit.A"
        threat_id = "2147654841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neojit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 25 01 00 00 80 79 05 48 83 c8 fe 40 85 c0 0f 85 ?? ?? 00 00 e9 0f b6 86 ?? ?? ?? ?? 0f b6 0a 2a c8 f6 d1 32 c8 88 0a e9 ?? ?? 00 00 00 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = {6a 73 ff d0 e9 ?? ?? ?? ?? 00 00 00 00 0a 00 68 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 73 ff d0 eb ?? 00 00 00 00 0a 00 68 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 fc c6 00 68 (e9|eb) 8b 45 fc 40 89 18 (e9|eb) 8b 45 fc 83 c0 05 c6 00 c3 (e9|eb) ff 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

