rule Worm_Win32_Catchdens_A_2147640343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Catchdens.A"
        threat_id = "2147640343"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Catchdens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 2f 75 10 80 78 01 62 75 0a}  //weight: 1, accuracy: High
        $x_1_2 = {80 38 2f 75 22 8a 48 01 80 f9 62 75 1a 80 78 02 69}  //weight: 1, accuracy: High
        $x_1_3 = {0f 00 45 f4 38 5d f4 74 09 38 5d f5 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {30 0c 30 fe c1 40 3b [0-2] 72}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c9 a8 01 75 ?? d1 e8 41 83 f9 1a 7c f4 8b [0-6] eb 06 83 c1 41}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b7 c8 a1 ?? ?? ?? ?? 33 d2 05 f8 00 00 00 66 39 08 74 12 42 40 40 83 fa 08 7c f3}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 61 58 6a 75 66 89 45 ?? 58 6a 74 66 89 45 ?? 58 6a 6f 66 89 45 ?? 58 6a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

