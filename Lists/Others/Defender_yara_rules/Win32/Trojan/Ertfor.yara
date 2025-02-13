rule Trojan_Win32_Ertfor_A_2147602727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ertfor.A"
        threat_id = "2147602727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ertfor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {eb 48 6a 00 68 ?? ?? 40 00 6a 01 68 ?? ?? 40 00 ff b5 ?? ?? ff ff e8 ?? ?? 00 00 a0 ?? ?? 40 00 32 85 ?? ?? ff ff a2 ?? ?? 40 00 6a 00}  //weight: 3, accuracy: Low
        $x_3_2 = {0f 84 f2 00 00 00 89 85 fc fd ff ff c7 85 d8 fd ff ff 14 00 00 00 eb 21 6a 00 68 21 28 00 10 6a 08 8d 85 e4 fd ff ff}  //weight: 3, accuracy: High
        $x_1_3 = {33 c5 eb 05 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 49 4e 49 44 00 45 52 52 4f 52 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 69 6e 6c 6f 67 61 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {70 32 68 68 72 2e 62 61 74 00 3a}  //weight: 1, accuracy: High
        $x_1_7 = "?id=%s&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ertfor_B_2147627204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ertfor.B"
        threat_id = "2147627204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ertfor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 3d 23 23 23 23 06 00 8d bd}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 11 8a 07 32 85 ?? ?? ?? ?? 88 07 47 ff 8d}  //weight: 1, accuracy: Low
        $x_1_3 = "?id=%s&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

