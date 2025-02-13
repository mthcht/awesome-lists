rule TrojanClicker_Win32_Sassrye_A_2147626341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Sassrye.A"
        threat_id = "2147626341"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Sassrye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 27 80 3c 1e 7c 75 20 40 c6 04 1e 00 83 f8 01 75 08 03 fe 89 3c 24 8d 7b 01 83 f8 02 75 09}  //weight: 2, accuracy: High
        $x_2_2 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d 00 44 00 00 75 ed 5a 5e 5b c3 07 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 2, accuracy: Low
        $x_1_3 = {8b d6 83 c2 04 88 02 c6 03 e9 47 89 2f}  //weight: 1, accuracy: High
        $x_1_4 = "_SYSTEM_SEARCH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

