rule TrojanDropper_Win32_Beastdoor_DV_2147606743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Beastdoor.DV"
        threat_id = "2147606743"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 10 01 00 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 ba 05 01 00 00 b8 ?? ?? 40 00 8a 08 32 0b 88 08 40 4a 75 f6 33 c0 8a 03 31 05 ?? ?? 40 00 31 05 ?? ?? 40 00 5b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 85 d2 72 11 42 33 c0 33 c9 8a 0c 03 33 ce 88 0c 03 40 4a 75 f2 46 81 fe c9 00 00 00 75 df 8b 55 f8 85 d2 72 13 42 33 c0 8a 0c 03}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 33 c0 a0 ?? ?? 40 00 31 05 ?? ?? 40 00 e8 ?? ?? ff ff 8d 45 c4 ba ?? ?? 40 00 b9 05 01 00 00 e8 ?? ?? ff ff 8b 45 c4 8b 0d ?? ?? 40 00 8b 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

