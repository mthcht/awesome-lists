rule TrojanDownloader_Win32_Idicaf_A_2147607515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Idicaf.A"
        threat_id = "2147607515"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Idicaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 08 84 c9 74 08 80 f1 ?? 88 08 40 eb f2}  //weight: 2, accuracy: Low
        $x_2_2 = {e9 b6 00 00 00 8b 4d f8 8b 51 01 89 55 e0 8b 45 e0 8b 4d f8 8d 54 01 05 89 55 d8 8b 45 d8 3b 45 0c 74 0f}  //weight: 2, accuracy: High
        $x_1_3 = {76 17 6a 19 53 e8 ?? ?? ff ff 8a 44 05 e0 59 88 04 3e 46 3b 75 0c 59 72 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {44 65 74 6f 75 72 44 6c 6c 2e 64 6c 6c 00 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 6f 6f 74 23 52 43 56 59 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Idicaf_B_2147610138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Idicaf.B"
        threat_id = "2147610138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Idicaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 83 fb 0c 74 21 6a 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 85 c0 74 c6}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 44 18 ff 50 8b c3 b9 0a 00 00 00 99 f7 f9 8a 82 ?? ?? ?? ?? 8a 54 1f ff 32 c2 5a 88 02 43 4e 75 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

