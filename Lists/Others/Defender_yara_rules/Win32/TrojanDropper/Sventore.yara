rule TrojanDropper_Win32_Sventore_A_2147697458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sventore.A"
        threat_id = "2147697458"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sventore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 66 33 04 7d ?? ?? ?? ?? 0f b7 c0 50 e8 ?? ?? ?? ?? 47 3b 7c 24 10 7c de}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sventore_A_2147697458_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sventore.A"
        threat_id = "2147697458"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sventore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 66 33 04 7d ?? ?? ?? ?? 0f b7 c0 50 e8 ?? ?? ?? ?? 47 3b [0-3] 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f9 66 8b 8c 56 ?? ?? ?? ?? 66 33 0c 55 ?? ?? ?? ?? 42 66 89 8c 57 ?? ?? ?? ?? 3b 55 0c 7c e2}  //weight: 1, accuracy: Low
        $x_1_3 = {2b c8 66 8b 84 73 ?? ?? ?? ?? 66 33 04 75 ?? ?? ?? ?? 66 89 84 71 ?? ?? ?? ?? 46 3b f2 7c e3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 56 14 0f b7 d8 83 fa 08 72 04 10 00 66 8b 84 78 ?? ?? ?? ?? 66 33 04 7d}  //weight: 1, accuracy: Low
        $x_1_5 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6}  //weight: 1, accuracy: High
        $x_1_6 = {50 75 15 80 7c ?? 01 4b 75 0e 80 7c ?? 02 05 75 07 80 7c ?? 03 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

