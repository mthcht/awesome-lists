rule Ransom_Win32_Mespinoza_SA_2147913041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mespinoza.SA"
        threat_id = "2147913041"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespinoza"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d 9c e8 ?? ?? ?? ?? 83 eb 01 75 e7 8b 4d 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {89 7d 0c c6 45 fc 01 85 ff 74 46 56 8b cf e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d c4 8b 7d c0 6a ff 6a 01}  //weight: 1, accuracy: High
        $x_1_4 = {89 1f 89 5f 04 6a 01 89 5d fc e8 ?? ?? ?? ?? 59 89 47 04}  //weight: 1, accuracy: Low
        $x_1_5 = {03 c1 3b c1 73 34 8b de 8b f1 2b f0}  //weight: 1, accuracy: High
        $x_1_6 = {75 f9 2b d6 8d b5 f8 fe ff ff 8d 5e 01 8a 06 46 84 c0}  //weight: 1, accuracy: High
        $x_1_7 = {83 e0 3f 6b d0 30 89 5d e4 8b 04 9d 00 b0 47 00 89 45 d4 89 55 e8 8a 5c 10 29}  //weight: 1, accuracy: High
        $x_1_8 = {8b 6c 24 0c 56 57 55 8b f9 e8 ?? ?? ?? ?? 8b 37}  //weight: 1, accuracy: Low
        $x_1_9 = {64 a3 00 00 00 00 89 65 f0 8b 75 08 8b 7d 0c 89 75 ec c7 45 fc 00 00 00 00 0f 1f 44 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {8b c3 2b c2 89 47 14 8b 75 08 8b ce e8 ?? ?? ?? ?? 84 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_Win32_Mespinoza_SB_2147913042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mespinoza.SB"
        threat_id = "2147913042"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespinoza"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {41 84 c0 75 ?? 2b ce 8b 35 ?? ?? ?? ?? 8d 41 01 50 (50|2d|5f) 6a 07 6a 00 68 ?? ?? ?? ?? ff (70|2d|7f) ?? ff (d0|2d|df) 6a 05 68 ?? ?? ?? ?? 6a 07 6a 00 68 ?? ?? ?? ?? ff (70|2d|7f) ?? ff (d0|2d|df) ff (70|2d|7f) ?? ff 15 ?? ?? ?? ?? 8b (40|2d|4f) ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d c3 4f 00 8a (00|2d|0f)}  //weight: 100, accuracy: Low
        $x_1_2 = "n.pysa" ascii //weight: 1
        $x_1_3 = "%s\\Readme.README" ascii //weight: 1
        $x_1_4 = "Every byte on any types of your devices was encrypted." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

