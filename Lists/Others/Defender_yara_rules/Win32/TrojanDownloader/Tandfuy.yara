rule TrojanDownloader_Win32_Tandfuy_A_2147684327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tandfuy.A"
        threat_id = "2147684327"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tandfuy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net stop MsMpSvc" ascii //weight: 1
        $x_1_2 = {00 5c 75 6e 69 6e 73 30 30 30 2e 61 79 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 75 04 83 c4 ?? c3 8b 4c 24 ?? 53 6a 00 6a 00 6a 00 6a 00 51 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tandfuy_B_2147684328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tandfuy.B"
        threat_id = "2147684328"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tandfuy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 04 b2 ?? 8a 01 84 c0 74 0e 32 c2 88 01 8a 41 01 41 fe ca 84 c0 75 f2 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {85 f6 89 74 24 ?? 75 05 5e 83 c4 ?? c3 8b 44 24 ?? 53 6a 00 6a 00 6a 00 6a 00 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tandfuy_C_2147687579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tandfuy.C"
        threat_id = "2147687579"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tandfuy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 80 38 00 b1 fe 74 0f eb 03 8d 49 00 30 08 40 fe c9 80 38 00 75 f6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {66 63 73 74 2e 63 6f 2e 6b 72 2f 62 6f 61 72 64 2f 64 61 74 61 2f 69 6e 73 69 64 65 74 6f 6f 6c 73 31 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 74 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {2b c2 4f 8a 4f 01 47 84 c9 75 f8 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 8d 54 24 08 83 e1 03 52 f3 a4 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

