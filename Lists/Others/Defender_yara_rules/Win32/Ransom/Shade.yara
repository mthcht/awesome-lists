rule Ransom_Win32_Shade_B_2147733595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shade.B!bit"
        threat_id = "2147733595"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shade"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 ?? 00 00 00 00 a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 0f b6 0c 0a f7 d9 8b 15 ?? ?? ?? ?? 0f b6 04 02 2b c1 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b ff 8b ca a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 0b a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c2 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Shade_C_2147733645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shade.C!bit"
        threat_id = "2147733645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shade"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 eb 00 eb 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 83 e8 0b a3 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 83 c2 0b a1 ?? ?? ?? 00 8b ff 8b ca a3 ?? ?? ?? 00 31 0d ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 c7 45 fc 00 00 00 00 a1 ?? ?? ?? 00 03 05 ?? ?? ?? 00 0f b6 08 f7 d9 8b 15 ?? ?? ?? 00 03 15 ?? ?? ?? 00 0f b6 02 2b c1 8b 0d ?? ?? ?? 00 03 0d ?? ?? ?? 00 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Shade_C_2147735695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shade.C"
        threat_id = "2147735695"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shade"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 01 a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 31 73 21 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 0f b6 11 83 ea 02 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 10 eb c9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d 59 11 00 00 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 59 11 00 00 a1 ?? ?? ?? ?? 8b ff 8b ca a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d a0 7e 4f 00 8b 15 ?? ?? ?? ?? 89 11}  //weight: 2, accuracy: Low
        $x_1_3 = "t34rfseTdgfQ111" ascii //weight: 1
        $x_1_4 = "GetSodu*eHa dleG" ascii //weight: 1
        $x_1_5 = "qtuglPritecz" ascii //weight: 1
        $x_1_6 = "Wr/teF/le" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Shade_PA_2147743916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shade.PA!MTB"
        threat_id = "2147743916"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shade"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {81 ff f5 11 00 00 75 13 56 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 95 ?? ?? ff ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d ?? ?? ?? 00 c1 e8 10 30 04 13 43 3b df 7c c6}  //weight: 20, accuracy: Low
        $x_20_2 = {81 ff f5 11 00 00 75 04 6a 00 ff d3 69 0d ?? ?? ?? ?? fd 43 03 00 8d 04 2e 46 81 c1 c3 9e 26 00 89 0d ?? ?? ?? ?? c1 e9 10 30 08 3b f7 7c d1}  //weight: 20, accuracy: Low
        $x_20_3 = {81 ff f5 11 00 00 75 0a 6a 00 ff d3 8b 8d ?? ?? ff ff 69 05 ?? ?? ?? ?? fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 30 04 0e 46 3b f7 7c cf}  //weight: 20, accuracy: Low
        $x_1_4 = {51 6a 40 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {51 6a 40 50 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

