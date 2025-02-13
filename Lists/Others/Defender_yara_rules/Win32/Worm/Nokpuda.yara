rule Worm_Win32_Nokpuda_A_2147644606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nokpuda.A"
        threat_id = "2147644606"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokpuda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 10 ff 8b c3 83 c0 e0 83 e8 5b 73 1f b8 5a 00 00 00 e8 ?? ?? ?? ?? f7 6d f4 03 d8 83 fb 20 7c 05 83 fb 7a 7e 06 6b 45 f4 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {b3 43 8d 85 28 fe ff ff 8b d3 e8 ?? ?? ?? ?? 8d 85 28 fe ff ff ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 28 fe ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 (02|04) 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Nokpuda_B_2147670673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nokpuda.B"
        threat_id = "2147670673"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokpuda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b c3 83 c0 e0 83 e8 5b 73 1f b8 5a 00 00 00 e8 ?? ?? ?? ?? f7 6d f4 03 d8 83 fb 20 7c 05 83 fb 7a 7e 06}  //weight: 3, accuracy: Low
        $x_3_2 = {c6 45 ef 43 8d 45 ?? 8a 55 ef e8 [0-31] 83 f8 03}  //weight: 3, accuracy: Low
        $x_1_3 = {5c 75 70 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 74 6d 70 2e 65 78 65 00 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "@ping -n 5 localhost> nul" ascii //weight: 1
        $x_1_6 = {64 6f 77 6e 61 6e 64 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 6f 77 6e 32 63 6f 75 6e 74 72 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 74 74 70 66 6c 6f 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

