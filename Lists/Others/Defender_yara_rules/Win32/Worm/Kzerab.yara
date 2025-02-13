rule Worm_Win32_Kzerab_A_2147615791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kzerab.A"
        threat_id = "2147615791"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kzerab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 89 45 e0 8d 45 dc 50 68 ?? ?? ?? ?? 68 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 07 33 c0 e9}  //weight: 1, accuracy: Low
        $x_2_2 = {81 7d f4 f5 7a 00 00 73 39 c7 45 d0 00 00 00 00 eb 09 8b 55 d0 83 c2 01 89 55 d0 83 7d d0 04 73 1f}  //weight: 2, accuracy: High
        $x_2_3 = {81 7d fc 09 0a 00 00 73 3b c7 45 f8 00 00 00 00 eb 09 8b 4d f8 83 c1 01 89 4d f8 83 7d f8 04 73 21}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

