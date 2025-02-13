rule TrojanSpy_Win32_Swotter_A_2147724812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swotter.A!bit"
        threat_id = "2147724812"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swotter"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 18 00 00 00 8b 40 30 89 45 fc 8b 4d fc 8b 51 0c 89 55 f8 c7 45 fc 00 00 00 00 8b 45 f8 8b 40 0c 89 45 fc 8b 75 fc 83 7e 18 00 74 35 8b 7d 08 8d a4 24 00 00 00 00 8b 46 30 50 8d 8d f4 fe ff ff 51 e8 ?? ?? ?? 00 8d 95 ?? ?? ?? ff 52 57 e8 ?? ?? ?? ff 83 c4 10 85 c0 75 0f 8b 36 39 46 18 75 d5}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 3a 8b c8 c1 e9 18 33 cf 81 e1 ff 00 00 00 c1 e0 08 33 84 8d ?? ?? ?? ?? 42 4e 75 e2}  //weight: 1, accuracy: Low
        $x_1_3 = {68 e2 1a 4e 0b e8 ?? ?? ?? ff 68 a6 68 36 f4 6a 00 6a 00 50 8b 45 08 50 e8 ?? ?? ?? ff 83 c4 18 85 c0 74 d7 8b 4d 10 51 6a 00 56 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

