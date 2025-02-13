rule TrojanDropper_Win32_Becues_A_2147627633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Becues.A"
        threat_id = "2147627633"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Becues"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 4c 33 f6 3b c3 76 0d 8a 4c 35 e0 30 4c 35 ec 46 3b f0 72 f3 6a 01 53 f7 d8 50 ff 75 f8 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Becues_B_2147627827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Becues.B"
        threat_id = "2147627827"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Becues"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c2 b2 03 f6 ea 02 44 34 ?? 32 d8 88 5c 34 ?? 46 3b f1 72 dc 6a 01 6a 00 f7 d9 51 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Becues_C_2147627986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Becues.C"
        threat_id = "2147627986"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Becues"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 85 c0 76 0d 8a 54 0c ?? 30 54 0c 14 41 3b c8 72 f3 6a 01 6a 00 f7 d8 50 ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 3b c8 72 f1 6a 01 6a 00 f7 d8 50 ?? ff 08 00 8a 54 0c ?? 30 54 0c 03 01 01 01 14 24 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

