rule TrojanDropper_Win32_Jscrpt_A_2147724810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jscrpt.A!bit"
        threat_id = "2147724810"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jscrpt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4b 08 89 4d fc 89 4b 0c 51 c6 45 fc 01 51 c7 43 04 01 00 00 00 ff 15 ?? ?? ?? 00 c7 45 ?? ?? ?? ?? ?? 33 c9 c7 45 ?? ?? ?? ?? ?? 6a ?? 58 d3 f8 30 44 0d ?? 41 83 f9 07 72 f1}  //weight: 1, accuracy: Low
        $x_2_2 = {8b d7 d3 ea 83 c1 08 88 14 18 40 83 f9 20 72 f0 8b 7d f8 85 ff 74 13 8b 4d f4 8b c6 83 e0 03 8a 04 18 30 04 0e 46 3b f7 72 f0}  //weight: 2, accuracy: High
        $x_1_3 = {8b 06 8b 08 8a 82 ?? ?? ?? 00 88 04 0a 42 8b 06 3b 50 04 72 eb 8b 0e 8b 51 04 8b 09 4a e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {56 8b d8 53 6a ff ff 37 33 ff 57 57 ff 15 ?? ?? ?? 00 8b 75 ?? 57 57 6a 02 8b 4e 0c 57 57 57 8b 11 57 68 ?? ?? ?? 00 53 51 ff 52 14 8b 46 08 6a 02 50 8b 08 ff 51 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

