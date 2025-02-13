rule Worm_Win32_Mofksys_A_2147681841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mofksys.gen!A"
        threat_id = "2147681841"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 93 24 49 92 2b ca 0f 80 3f 02 00 00 f7 e9 03 d1 c1 fa 03 8b ca c1 e9 1f}  //weight: 2, accuracy: High
        $x_2_2 = {8d 55 d4 52 66 8b 55 be 66 6b d2 28 0f 80 48 02 00 00 0f bf d2 52 8b 49 0c}  //weight: 2, accuracy: High
        $x_1_3 = "</xCommand>" wide //weight: 1
        $x_1_4 = "</DblClk>" wide //weight: 1
        $x_1_5 = "<Download>" wide //weight: 1
        $x_1_6 = "&HA8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Mofksys_NA_2147743070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mofksys.NA!MTB"
        threat_id = "2147743070"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 88 0a c3 0f b7 08 66 89 0a c3 66 8b 08 8a 40 ?? 66 89 0a 88 42 ?? c3 8b 08 89 0a c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 b9 4e 00 00 00 99 f7 f9 58 2b c2 b9 ?? 00 00 00 99 f7 f9 8b c8 49 6b c1 ?? 50 8b 45 ?? 5a 2b c2 83 e8 ?? be ?? 00 00 00 99 f7 fe 8b f0}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 13 20 00 00 0f 8f be 00 00 00 0f 84 62 02 00 00 3d ?? ?? 00 00 7f 5e 0f 84 ce 01 00 00 3d ?? 00 00 00 7f 2f 0f 84 09 02 00 00 83 e8 ?? 0f 84 34 01 00 00 83 e8 ?? 0f 84 43 01 00 00 83 e8 ?? 0f 84 ca 01 00 00 83 e8 ?? 0f 84 d9 01 00 00 e9 79 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mofksys_GTN_2147922423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mofksys.GTN!MTB"
        threat_id = "2147922423"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c5 24 5f 33 57 cd b9 d5 63 ef a8 b6 0e b2 f8 95 93}  //weight: 5, accuracy: High
        $x_5_2 = {06 36 4d 14 f4 34 41 b4 71 a2 ?? ?? ?? ?? 95 e4 c4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

