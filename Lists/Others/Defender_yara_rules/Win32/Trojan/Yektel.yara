rule Trojan_Win32_Yektel_C_126222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yektel.C"
        threat_id = "126222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yektel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3e c3 75 [0-5] ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {4a 03 0c 24 80 3a 90 75}  //weight: 1, accuracy: High
        $x_1_3 = {01 f8 c2 08 00 60}  //weight: 1, accuracy: High
        $x_1_4 = {9d 83 f8 00 74 05 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yektel_F_132998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yektel.F"
        threat_id = "132998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yektel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 72 65 65 73 63 61 6e 2e 70 68 70 3f [0-1] 69 64 3d 25 76 61 72 25 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {50 49 44 77 6d 73 69 64 00 00 03}  //weight: 1, accuracy: High
        $x_1_3 = {09 62 74 6e 47 6f 6f 67 6c 65 74 03 00 00 01 00 08 62 74 6e 59 61 68 6f 6f}  //weight: 1, accuracy: High
        $x_2_4 = {e8 df fe ff ff 83 7d f0 00 0f 84 e1 00 00 00 0f b6 05 05 00 b8 01 00 00 80}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

