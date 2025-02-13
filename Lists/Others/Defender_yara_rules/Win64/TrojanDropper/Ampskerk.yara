rule TrojanDropper_Win64_Ampskerk_B_2147693035_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Ampskerk.B!dha"
        threat_id = "2147693035"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Ampskerk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {b8 07 00 00 00 66 89 44 24 42 b8 05 00 00 00 41 bb d8 07 00 00 66 89 44 24 44 b8 18 00 00 00 48 8d 54 24 50 66 89 44 24 46 b8 0b 00 00 00 48 8d 4c 24 40 66 89 44 24 48 b8 10 00 00 00 66 44 89 5c 24 40 66 89 44 24 4a b8 38 00 00 00 66 44 89 6c 24 4e 66 89 44 24 4c ff 15 20 9e 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {66 66 66 66 66 66 0f 1f 84 00 00 00}  //weight: 3, accuracy: High
        $x_3_3 = {c7 44 24 70 25 53 79 73 c7 84 24 88 00 00 00 63 68 6f 73 c7 44 24 74 74 65 6d 52 c7 44 24 78 6f 6f 74 25 c7 84 24 94 00 00 00 20 6e 65 74 c7 44 24 7c 5c 53 79 73 c7 84 24 80 00 00 00 74 65 6d 33 c7 84 24 90 00 00 00 65 20 2d 6b c7 84 24 84 00 00 00 32 5c 73 76 c7 84 24 8c 00 00 00 74 2e 65 78}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

