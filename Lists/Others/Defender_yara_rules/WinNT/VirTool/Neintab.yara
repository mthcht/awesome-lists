rule VirTool_WinNT_Neintab_A_2147602326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Neintab.A"
        threat_id = "2147602326"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Neintab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 51 70 89 15 ?? ?? 01 00 8b 45 08 8b 48 40 89 0d ?? ?? 01 00 8d 55 fc 52 68 ?? ?? 01 00 8b 45 08 8b 48 0c 51 e8 ?? ?? 00 00 89 45 d4 68}  //weight: 4, accuracy: Low
        $x_4_2 = {83 7d e4 00 75 05 e9 12 01 00 00 8d 45 f4 50 8b 4d ec 51 8b 55 e4 52 6a 0b e8 ?? ?? 00 00 89 45 f0 81 7d f0 04 00 00 c0 75 54}  //weight: 4, accuracy: Low
        $x_1_3 = "init nklib version %s  built %s" ascii //weight: 1
        $x_1_4 = {64 3a 5c 70 72 6f 6a 5c 6e 6b [0-7] 5c 73 72 63 5c 6e 6b 6c 69 62 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {64 3a 5c 70 72 6f 6a 5c 6e 6b [0-7] 5c 6f 75 74 5c 69 33 38 36 5c 6e 6b 76 32 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

