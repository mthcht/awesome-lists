rule Backdoor_Win32_Bedep_A_2147690257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bedep.A"
        threat_id = "2147690257"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 fc 0f be 1e f6 ea 8a d3 2a d0 8b 45 fc 80 ea ?? 46 88 11 c1 c8 08 01 45 fc 41 ff 4d 08 8b d3 75 dd}  //weight: 2, accuracy: Low
        $x_2_2 = {33 5d 1c 69 db 65 9d 01 00 03 d9 33 d8 ff 4d f8 83 7d f8 00 7f ea 8b 4d 10 69 ff 83 02 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {80 78 20 23 0f 85 ?? ?? ?? ?? 80 78 31 23 0f 85 ?? ?? ?? ?? 8d 44 08 ff 80 38 23}  //weight: 1, accuracy: Low
        $x_1_4 = {85 c0 75 01 c3 59 8b ?? ?? ?? ?? ?? a9 01 00 00 00 74 0b 6a 00 83 f0 01 8b ?? ?? ?? ?? ?? 50 51 ff e2}  //weight: 1, accuracy: Low
        $x_2_5 = {b8 7b 00 00 c0 78 ?? 81 39 2a d8 12 1c}  //weight: 2, accuracy: Low
        $x_1_6 = {ff d2 41 b8 2b 00 00 00 45 8b 8d bc 00 00 00 41 8b a5 c8 00 00 00 41 8e d0}  //weight: 1, accuracy: High
        $x_1_7 = {c7 40 60 45 76 38 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bedep_B_2147690321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bedep.B!!Bedep.gen!B"
        threat_id = "2147690321"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedep"
        severity = "Critical"
        info = "Bedep: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 fc 0f be 1e f6 ea 8a d3 2a d0 8b 45 fc 80 ea ?? 46 88 11 c1 c8 08 01 45 fc 41 ff 4d 08 8b d3 75 dd}  //weight: 2, accuracy: Low
        $x_2_2 = {33 5d 1c 69 db 65 9d 01 00 03 d9 33 d8 ff 4d f8 83 7d f8 00 7f ea 8b 4d 10 69 ff 83 02 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {80 78 20 23 0f 85 ?? ?? ?? ?? 80 78 31 23 0f 85 ?? ?? ?? ?? 8d 44 08 ff 80 38 23}  //weight: 1, accuracy: Low
        $x_1_4 = {85 c0 75 01 c3 59 8b ?? ?? ?? ?? ?? a9 01 00 00 00 74 0b 6a 00 83 f0 01 8b ?? ?? ?? ?? ?? 50 51 ff e2}  //weight: 1, accuracy: Low
        $x_2_5 = {b8 7b 00 00 c0 78 ?? 81 39 2a d8 12 1c}  //weight: 2, accuracy: Low
        $x_1_6 = {5c 78 46 46 d2 41 b8 2b 00 00 00 45 8b 8d bc 00 00 00 41 8b a5 c8 00 00 00 41 8e d0}  //weight: 1, accuracy: High
        $x_1_7 = {c7 40 60 45 76 38 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

