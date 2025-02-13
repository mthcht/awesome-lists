rule TrojanDropper_Win32_Vareids_A_2147628231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vareids.A"
        threat_id = "2147628231"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vareids"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 46 24 20 00 00 e0 8b 4f 28 2b 4e 0c 89 5d fc 8b 5d f8 81 e9}  //weight: 2, accuracy: High
        $x_2_2 = {58 ab e2 fc 8b 7c 24 14 83 c4 14 5a 8d aa ?? ?? ?? ?? 55}  //weight: 2, accuracy: Low
        $x_1_3 = {03 f8 0f b7 47 06 40 40 6b c0 05 03 47 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

