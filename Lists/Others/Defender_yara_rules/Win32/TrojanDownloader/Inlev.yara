rule TrojanDownloader_Win32_Inlev_A_2147681389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inlev.A"
        threat_id = "2147681389"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inlev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 06 48 54 54 50 c7 46 04 31 2e 38 20 c7 46 08 47 45 54 00 66}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 ff 75 ?? ff 55 ?? (3b c6|83) 75 06 ff 75 ?? ff 55 ?? 6a 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Inlev_B_2147681594_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inlev.B"
        threat_id = "2147681594"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inlev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 bd b5 b8 8f [0-64] e8 ?? ?? ?? ?? 59 59 ff d0}  //weight: 10, accuracy: Low
        $x_1_2 = {68 5b bc 4a 6a c7 84 24 ?? ?? 00 00 77 73 32 5f c7 84 24 ?? ?? 00 00 33 32 2e 64 c7 84 24 ?? ?? 00 00 6c 6c 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 64 77 79 0e [0-24] c7 ?? 48 54 54 50}  //weight: 1, accuracy: Low
        $x_1_4 = {68 26 80 ac c8 [0-4] c7 44 24 ?? 77 73 32 5f c7 44 24 ?? 33 32 2e 64 c7 44 24 ?? 6c 6c 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

