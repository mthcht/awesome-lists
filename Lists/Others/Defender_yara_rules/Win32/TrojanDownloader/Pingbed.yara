rule TrojanDownloader_Win32_Pingbed_A_2147629380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pingbed.A"
        threat_id = "2147629380"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 6a 10 57 68 ?? ?? 00 00 56 56 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 10 57}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 8b f0 ff 15 ?? ?? ?? ?? 3b ?? 76 ?? 56 ?? 68 ff 0f 1f 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pingbed_A_2147629380_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pingbed.A"
        threat_id = "2147629380"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 31 ff 32 04 31 8a d0 c0 ea 03 c0 e0 05 0a d0 88 14 31 49 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 32 44 24 0c 8a c8 c0 e9 03 c0 e0 05 0a c8 88 0e 5e}  //weight: 1, accuracy: High
        $x_1_3 = {8a 06 5f 8a c8 c0 e1 03 c0 e8 05 0a c8 32 4c 24 10 39 7c 24 14 88 0e}  //weight: 1, accuracy: High
        $x_1_4 = {8a 14 37 8d 04 37 8a ca c0 e1 03 c0 ea 05 0a ca 88 08 8a 54 37 ff 32 d1 47 3b 7c 24 14 88 10 72 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Pingbed_B_2147633372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pingbed.B"
        threat_id = "2147633372"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 01 30 10 40 4e 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {80 7d 08 1b 75 12 80 7d 09 34 75 0c 80 7d 0a 5e 75 06 80 7d 0b 2d 74 08 f6 46 0c 10 75 73 eb cf}  //weight: 1, accuracy: High
        $x_1_3 = {80 bd 85 f9 ff ff 75 75 16 80 bd 86 f9 ff ff 69 75 0d 80 bd 87 f9 ff ff 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Pingbed_C_2147645824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pingbed.C"
        threat_id = "2147645824"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d 01 00 74 20 6a 00 8b 4d f8 51 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d 04 00 75 0b 68 f4 01 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "!@#tiuq#@!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

