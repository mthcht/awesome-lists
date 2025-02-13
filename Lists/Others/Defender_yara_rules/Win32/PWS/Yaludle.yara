rule PWS_Win32_Yaludle_A_2147608165_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yaludle.A"
        threat_id = "2147608165"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yaludle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 11 50 46 e8 ?? ?? ff ff 88 07 8a 06 47 (59|84) 75 ef 80 27 00 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 50 56 57 6a 13 [0-16] f3 a5 [0-16] 66 a5 [0-12] 50 a4 e8 ba ff ff ff [0-5] 59 [0-5] 5e 74 14 8d 4d b0 [0-7] 2b c1 [0-7] 83 c0 27 [0-5] f7 f9 8a 44 15 b0 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Yaludle_B_2147625494_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yaludle.B"
        threat_id = "2147625494"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yaludle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 1d 56 8b 74 24 0c 50 47 e8 87 ff ff ff 88 06 8a 07 83 c4 04 46 84 c0 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {c1 4d fc 0d 0f be 01 8b 55 fc 03 d0 8a 41 01 41 84 c0 89 55 fc 75 e9}  //weight: 1, accuracy: High
        $x_1_3 = {b8 d3 4d 62 10 f7 e2 8b c2 c1 e8 06 33 d2 b9 80 51 01 00 f7 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Yaludle_D_2147635803_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yaludle.D"
        threat_id = "2147635803"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yaludle"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 41 01 41 84 c0 75 f4 53 8a 19 33 c0 3a da 0f 95 c0 48 5b 23 c1 c3}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 74 16 2d ?? ?? ?? ?? b9 ?? 00 00 00 83 c0 ?? 99 f7 f9 8a 9a ?? ?? ?? ?? 88 1c 2e 8a 46 01 47 46 84 c0 75 c2}  //weight: 1, accuracy: Low
        $x_2_3 = {68 4d a0 07 6c 56 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Yaludle_D_2147635803_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yaludle.D"
        threat_id = "2147635803"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yaludle"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 eb f1 8a 08 2a 4c 24 08 f6 d9 1b c9 f7 d1 23 c1}  //weight: 1, accuracy: High
        $x_1_2 = {59 74 13 2b c6 6a ?? 83 c0 ?? 59 99 f7 f9 5e 8a 82 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_2_3 = {74 62 ff 45 f8 83 45 fc 08 39 75 f8 72 e1 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 39 5d f4 74 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Yaludle_F_2147643520_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yaludle.F"
        threat_id = "2147643520"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yaludle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 75 03 6a 0a 58 69 c0 e8 03 00 00 50 e8 ?? ?? ?? ?? 68 10 27 00 00 ff 15 ?? ?? ?? ?? eb d9 07 00 6a 0a e8}  //weight: 2, accuracy: Low
        $x_2_2 = {85 c0 75 05 b8 0a 00 00 00 8d 04 80 8d 04 80 8d 04 80 c1 e0 03 50 e8 ?? ?? ?? ?? 68 10 27 00 00 ff 15 ?? ?? ?? ?? eb d1 07 00 6a 0a e8}  //weight: 2, accuracy: Low
        $x_1_3 = {83 c0 25 99 b9 4a 00 00 00 f7 f9 5b 8a 82}  //weight: 1, accuracy: High
        $x_1_4 = {2b c6 83 c0 25 6a 4a 99 59 f7 f9 5e 8a 82}  //weight: 1, accuracy: High
        $x_1_5 = {2b c7 6a 4c 83 c0 26 59 99 f7 f9 8a 9a}  //weight: 1, accuracy: High
        $x_1_6 = {0f b7 47 02 43 83 c6 28 3b d8 7c}  //weight: 1, accuracy: High
        $x_1_7 = {40 eb f1 8a 08 2a 4c 24 08 f6 d9 1b c9 f7 d1 23 c1}  //weight: 1, accuracy: High
        $x_2_8 = {68 04 01 00 00 8d 44 24 04 50 e8 ?? ?? ?? ?? 68 03 01 00 00 8d 4c 24 04 51 6a 00 ff 15 ?? ?? ?? ?? 6a 04 6a 00 8d 54 24 08 52 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

