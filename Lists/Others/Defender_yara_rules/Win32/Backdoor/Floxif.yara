rule Backdoor_Win32_Floxif_A_2147723496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Floxif.gen!A"
        threat_id = "2147723496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 89 55 f8 3b d7 74 ?? 8b fa 33 c9 2b fb 8a 99 ?? ?? ?? 00 88 9c 0f ?? ?? ?? 00 c6 81 ?? ?? ?? 00 00 41 3b ce 7c e7 ff d2}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 64 a1 30 00 c7 40 04 00 00 c3 00 ff d0 8b 40 0c 8b 4d 08 8b 40 0c 8b 00 39 70 18 74 ?? 8b 50 30 66 83 7a 0c 33}  //weight: 1, accuracy: Low
        $x_1_3 = {74 07 c6 00 00 40 49 75 f9 6a 00 6a 01 ff 75 fc ff 55 e0}  //weight: 1, accuracy: High
        $x_1_4 = {68 54 53 4f 50 e8 ?? ?? ff ff 89 45 ?? 88 5d ?? 66 c7 45 ?? 2f 00 c7 04 24 50 54 54 48 e8 ?? ?? ff ff 89 45 ?? c7 04 24 31 2e 31 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {91 b8 81 c0 e8 ?? ?? ff ff 68 44 49 55 4d e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_6 = {91 b8 81 c0 e8 ?? ?? ff ff 68 44 49 43 54 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_7 = {91 b8 81 c0 e8 ?? ?? ff ff 68 44 49 4e 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_8 = {c7 45 e8 29 de 9f 00 e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Floxif_B_2147723528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Floxif.gen!B"
        threat_id = "2147723528"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" ascii //weight: 2
        $x_2_2 = {68 19 00 02 00 8d 45 ?? 6a 00 50 68 02 00 00 80 c7 45 ?? 30 30 31 00}  //weight: 2, accuracy: Low
        $x_1_3 = {8a d0 8a c1 b3 07 f6 eb 2c 33 32 c2 88 44 0d}  //weight: 1, accuracy: High
        $x_1_4 = {b8 17 93 28 f3 33 c8 89 7d ?? 89 0f}  //weight: 1, accuracy: Low
        $x_2_5 = {c7 00 03 00 00 00 50 8d 46 60 6a 00 50 ff 76 20 ff 52 14 fe 46 62}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Floxif_2147837904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Floxif.psyA!MTB"
        threat_id = "2147837904"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 8b 55 08 85 d2 75 15 e8 69 fe ff ff c7 00 16 00 00 00 e8 ?? ?? ?? ff 83 c8 ff 5d c3 83 6a 08 01 79 09 52 e8 ?? ?? ?? 00 59 5d c3 8b 02 8a 08 40 89 02 0f b6 c1 5d c3 8b ff 55 8b ec 5d e9 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {75 18 e8 49 ?? ?? ?? c7 00 16 00 00 00 e8 ?? ?? ?? ff 83 c8 ff e9 67 01 00 00 8b 40 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d ?? ?? ?? 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

