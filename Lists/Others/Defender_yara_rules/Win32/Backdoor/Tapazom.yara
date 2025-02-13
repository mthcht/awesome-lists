rule Backdoor_Win32_Tapazom_A_2147666526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tapazom.A"
        threat_id = "2147666526"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapazom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c7 45 f0 03 00 00 00 8d 75 f4 33 db 8d 45 ec 8b cb c1 e1 03 ba ff 00 00 00 d3 e2 23 16 8b cb c1 e1 03 d3 ea e8}  //weight: 100, accuracy: High
        $x_100_2 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 ?? ?? 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03}  //weight: 100, accuracy: Low
        $x_50_3 = "mzo.hopto.org:" ascii //weight: 50
        $x_30_4 = {89 45 e8 89 55 ec 83 7d ec 00 75 08 83 7d e8 00 77 bc eb 02 7f b8 84 db 74 0b 57 e8}  //weight: 30, accuracy: High
        $x_20_5 = "-core" ascii //weight: 20
        $x_20_6 = "Carvier" ascii //weight: 20
        $x_10_7 = "sytem32.dll" ascii //weight: 10
        $x_10_8 = "{12F48881-FF6D-43A1-B80B-9265C25CC9F6}\\" ascii //weight: 10
        $x_10_9 = {0a 00 00 00 47 45 54 53 45 52 56 45 52 7c}  //weight: 10, accuracy: High
        $x_10_10 = {05 00 00 00 48 41 52 4d 7c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 4 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_30_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tapazom_B_2147667482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tapazom.B"
        threat_id = "2147667482"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapazom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "280"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 ?? ?? 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03}  //weight: 200, accuracy: Low
        $x_50_2 = "mmzo.dyndns.org:1431" ascii //weight: 50
        $x_50_3 = "Carvier" ascii //weight: 50
        $x_30_4 = {07 49 6e 66 2e 65 78 65 08 55 74 69 6c 69 74 79}  //weight: 30, accuracy: High
        $x_30_5 = {16 48 49 44 2d 49 6e 74 65 72 66 61 63 65 73 20 44 65 76 69 63 65 ae 00}  //weight: 30, accuracy: High
        $x_10_6 = "utili.exe" ascii //weight: 10
        $x_10_7 = "wid.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 2 of ($x_30_*) and 2 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            ((1 of ($x_200_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tapazom_D_2147669019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tapazom.D"
        threat_id = "2147669019"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapazom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c7 45 f0 03 00 00 00 8d 75 f4 33 db 8d 45 ec 8b cb c1 e1 03 ba ff 00 00 00 d3 e2 23 16 8b cb c1 e1 03 d3 ea e8}  //weight: 100, accuracy: High
        $x_100_2 = {83 7d e8 ff 75 04 b3 01 eb 60 80 7d f7 0e 74 5a 80 7d f7 0a 74 22 80 7d f7 0d 74 1c 8d 85 d4 f8 ff ff 8a 55 f7 e8}  //weight: 100, accuracy: High
        $x_50_3 = "mzo.hopto.org:1431" ascii //weight: 50
        $x_50_4 = "-Multicore.exe" ascii //weight: 50
        $x_20_5 = "Carvier" ascii //weight: 20
        $x_10_6 = "dot3dlxe.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tapazom_F_2147669021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tapazom.F"
        threat_id = "2147669021"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapazom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {eb 60 83 7d ec ff 75 0a 83 7d e8 ff 75 04 b3 01 eb 60 80 7d f7 0e 74 5a 80 7d f7 0a 74 22 80 7d f7 0d 74 1c}  //weight: 100, accuracy: High
        $x_100_2 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 ?? ?? 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03}  //weight: 100, accuracy: Low
        $x_50_3 = "mmzo.dyndns.org:1143" ascii //weight: 50
        $x_50_4 = {0b 49 6e 63 6c 6f 75 64 2e 65 78 65}  //weight: 50, accuracy: High
        $x_20_5 = "HID-Device" ascii //weight: 20
        $x_20_6 = "mzsr64.dll" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tapazom_G_2147678805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tapazom.G"
        threat_id = "2147678805"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapazom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BTMemoryLoadLibary" ascii //weight: 1
        $x_1_2 = {5c 6d 65 6c 74 20 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 45 54 53 45 52 56 45 52 7c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

