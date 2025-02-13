rule TrojanDownloader_Win32_Climetop_A_2147624309_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Climetop.A"
        threat_id = "2147624309"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Climetop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 c1 80 33 ?? 43 e2 fa c3}  //weight: 4, accuracy: Low
        $x_1_2 = {ff d0 83 3d ?? ?? ?? ?? 64 74 11}  //weight: 1, accuracy: Low
        $x_1_3 = "wshell32.dll" ascii //weight: 1
        $x_1_4 = {74 88 6a 00 6a 01}  //weight: 1, accuracy: High
        $x_1_5 = "complite.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Climetop_B_2147627116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Climetop.B"
        threat_id = "2147627116"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Climetop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 09 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 09 0f 87 ?? ?? ff ff 6a 00 6a 04}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 83 c0 0c 8b 00 3b 70 18 75 f9}  //weight: 1, accuracy: High
        $x_1_3 = {74 63 89 c6 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 04 68 00 30 00 00 50 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 74 40}  //weight: 1, accuracy: Low
        $x_1_4 = {89 c1 80 33 ?? 43 e2 fa}  //weight: 1, accuracy: Low
        $x_1_5 = "{7849596a-48ea-486e-8937-a2a3009f31a9}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

