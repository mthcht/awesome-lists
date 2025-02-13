rule Backdoor_WinNT_Phdet_A_2147670386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Phdet.A"
        threat_id = "2147670386"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 7e 4b 54 1a}  //weight: 1, accuracy: High
        $x_1_2 = {68 e0 3c 96 a2}  //weight: 1, accuracy: High
        $x_1_3 = {68 31 a1 44 bc}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 f4 6e 74 6f 73}  //weight: 1, accuracy: High
        $x_1_5 = {8a 1c 38 30 1c 0e}  //weight: 1, accuracy: High
        $x_1_6 = {8b 46 28 03 c3 ff d0}  //weight: 1, accuracy: High
        $x_1_7 = {ff d0 3d 04 00 00 c0}  //weight: 1, accuracy: High
        $x_1_8 = {0f 01 4c 24 04 8b 44 24 06}  //weight: 1, accuracy: High
        $x_1_9 = {f3 aa 8b 02 25 ff ff ff fd 0d 00 00 00 08 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_WinNT_Phdet_B_2147670387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Phdet.B"
        threat_id = "2147670387"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {eb 0c 58 2b 05 ?? ?? ?? ?? 03 45 f8 ff e0 58}  //weight: 3, accuracy: Low
        $x_1_2 = {81 e1 00 f0 ff ff 06 00 8b ?? ?? 8b ?? 04}  //weight: 1, accuracy: Low
        $x_1_3 = {81 e2 00 f0 ff ff 06 00 8b ?? ?? 8b ?? 04}  //weight: 1, accuracy: Low
        $x_1_4 = {25 00 f0 ff ff 06 00 8b ?? ?? 8b ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Phdet_A_2147670388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Phdet.gen!A"
        threat_id = "2147670388"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Phdet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 c7 41 0c 0f 84 8b 4d 0c c7 41 0e 14 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {66 81 38 ff 25 75 10 8b 40 02 b9 ?? ?? ?? ?? 87 08 89 0d}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 05 59 59 75 0b 80 7d ?? b8 75 05 8b 46 01}  //weight: 2, accuracy: Low
        $x_2_4 = {81 3e 25 ff 0f 00 74 14 03 f8 03 f0 81 ff 00 01 00 00 72 dc 32 c0 5f 5e c9 c2 08 00 8b 46 0a 8d 44 06 0e 80 78 07 e8}  //weight: 2, accuracy: High
        $x_2_5 = {66 39 46 06 89 45 08 76 20 6a 01 68 ?? ?? ?? ?? 57 e8 ?? ?? ff ff 84 c0 75 18 0f b7 46 06}  //weight: 2, accuracy: Low
        $x_1_6 = {8b 45 08 03 c7 50 8d 85 f0 fe ff ff 50 e8 ?? ?? ?? ?? 47 3b 7b 04}  //weight: 1, accuracy: Low
        $x_1_7 = "RulesData" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Phdet_B_2147681682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Phdet.gen!B"
        threat_id = "2147681682"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Phdet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5e 04 0f b7 d1 03 c9 2b c1}  //weight: 1, accuracy: High
        $x_1_2 = {bf 64 86 00 00 66 3b d7 75}  //weight: 1, accuracy: High
        $x_1_3 = "_PYALOAD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

