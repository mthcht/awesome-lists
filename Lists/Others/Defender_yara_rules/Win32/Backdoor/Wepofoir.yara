rule Backdoor_Win32_Wepofoir_A_2147652394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wepofoir.A"
        threat_id = "2147652394"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wepofoir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 48 06 39 4d f8 7d 28 8b 55 f8 6b d2 28 8b 45 f8 6b c0 28 8b 4d ec 8b 44 01 08}  //weight: 2, accuracy: High
        $x_2_2 = {02 04 0f 25 ff 00 00 00 89 c7 41 3b 4d 0c 75 05 b9 00 00 00 00 8b 44 bb 08 89 06 89 54 bb 08 83 45 f0 10 81 7d f0 00 04 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {6b c9 14 8b 95 dc fb ff ff 83 7c 0a 04 05 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {75 4a 83 7d fc 40 7d 06 83 7d f0 00 7f 05}  //weight: 1, accuracy: High
        $x_1_5 = {83 7d fc 02 74 0b 83 7d fc 17 74 4e e9 92 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {83 f9 20 74 0e 8b 95 ?? ?? ff ff 0f be 02 83 f8 09 75 1e 8b 8d ?? ?? ff ff 0f be 11 85 d2 74 11 8b 85 ?? ?? ff ff 83 c0 01 89 85 ?? ?? ff ff eb c6}  //weight: 1, accuracy: Low
        $x_1_7 = "cscript /NoLogo /B " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

