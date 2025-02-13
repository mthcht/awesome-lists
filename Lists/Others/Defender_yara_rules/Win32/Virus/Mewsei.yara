rule Virus_Win32_Mewsei_A_2147690883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Mewsei.A"
        threat_id = "2147690883"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Mewsei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 f6 fd 43 03 00 81 c6 c3 9e 26 00 8b c6 c1 e8 10 25 ff 7f 00 00 33 d2 bb ff 00 00 00 f7 f3 8b 45 08 41 fe c2 88 54 0f ff 3b c8 72 d3}  //weight: 1, accuracy: High
        $x_1_2 = {f6 d9 30 0c ?? 42 ?? 3b ?? 72 eb 85 c0 74 09 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Mewsei_B_2147691384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Mewsei.B"
        threat_id = "2147691384"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Mewsei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 24 04 20 38 44 42 f7 83 f8 04 0f 96 c1}  //weight: 1, accuracy: High
        $x_1_2 = {ac ff ff ff 89 04 24 e8 55 fd ff ff 89 f3 03 1c 06 c7 04 24 24 28 00}  //weight: 1, accuracy: High
        $x_1_3 = {02 04 00 00 89 c6 85 ff 74 1f 8d 9d e4 fe ff ff 01 df}  //weight: 1, accuracy: High
        $x_1_4 = {ec 1c e8 a8 fe ff ff 84 c0 75 09 e8 86 ff ff ff 84 c0 74 0c}  //weight: 1, accuracy: High
        $x_1_5 = {b6 02 0f b6 19 38 d8 75 1a 84 c0 75 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

