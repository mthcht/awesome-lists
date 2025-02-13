rule Worm_Win32_Yoinoir_A_2147655273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yoinoir.A"
        threat_id = "2147655273"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoinoir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 02 75 19 8d 45 f8 8b d3 e8 ?? ?? ?? ?? 8b 55 f8 8b c6 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 83 fb 5b 75 b7}  //weight: 2, accuracy: Low
        $x_1_2 = {66 c7 45 ea 50 00 8d 45 da 50 e8 ?? ?? ?? ?? 85 c0 0f 94 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {67 70 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 73 65 41 75 74 6f 50 6c 61 79 3d 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

