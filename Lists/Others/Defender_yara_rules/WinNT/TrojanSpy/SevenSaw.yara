rule TrojanSpy_WinNT_SevenSaw_A_2147600057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:WinNT/SevenSaw.A!sys"
        threat_id = "2147600057"
        type = "TrojanSpy"
        platform = "WinNT: WinNT"
        family = "SevenSaw"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 9e 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 43 60 83 e8 24 89 70 1c 8b 74 24 10 68 ?? ?? ?? ?? 89 70 20 c6 40 03 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 66 81 48 1c 04 20 8b 45 fc 80 60 1c 7f 53}  //weight: 1, accuracy: High
        $x_1_3 = {68 44 64 6b 20 6a 0c 6a 00 c6 46 18 00 ff 15 ?? ?? ?? ?? 8b e8 8a 47 fe 88 45 08 8a 07}  //weight: 1, accuracy: Low
        $x_1_4 = {57 33 c0 50 b8 40 42 0f 00 50 8d 45 d0 50 ff 15 ?? ?? ?? ?? 57 57 57 57 8d 45 d0 50 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

