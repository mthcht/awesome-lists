rule VirTool_WinNT_Haxdoor_2147724163_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Haxdoor"
        threat_id = "2147724163"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Haxdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e8 3b 00 00 00 0b c0 75 32 68 60 04 01 00 68 98 04 01 00 e8 34 00 00 00 0b c0 75 1f 8b 75 08 c7 46 70 2d 03 01 00 c7 46 38 2d 03 01 00 c7 46 34 00 02 01 00 61 33 c0 c9 c2 08 00}  //weight: 10, accuracy: High
        $x_10_2 = {55 8b ec 56 57 53 8b 7d 0c 33 c0 89 47 1c 89 47 18 8b 77 60 80 3e 0e 75 29 8b 46 0c 3d 00 09 00 00 75 11 8b 7f 3c be fc 06 01 00 b9 d0 07 00 00 f3 a4 eb 0e}  //weight: 10, accuracy: High
        $x_1_3 = "\\DosDevices\\a311config" wide //weight: 1
        $x_1_4 = "\\Device\\a311config" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Haxdoor_2147724163_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Haxdoor"
        threat_id = "2147724163"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Haxdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 0c c7 40 18 00 00 00 00 [0-1] 83 60 1c 00 [0-1] 6a 00 ff 75 0c e8 ?? 03 00 00 83 c4 08 [0-1] b8 00 00 00 00 c9 c2 08 00}  //weight: 10, accuracy: Low
        $x_10_2 = {e8 4e 03 00 00 59 90 3b c8 75 (22|23) 68 c4 09 01 00 68 f4 09 01 00 e8 3f 03 00 00 8b 4d 08 [0-1] c7 41 38 e1 01 01 00 60 e8 48 00 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {e8 e1 02 00 00 0b c0 75 29 68 34 06 01 00 68 64 06 01 00 e8 d4 02 00 00 0b c0 75 16 8b 75 08 c7 46 38 40 02 01 00 b8 00 00 00 00 5f 5e 5b c9 c2 08 00}  //weight: 10, accuracy: High
        $x_1_4 = "\\DosDevices\\winm32" wide //weight: 1
        $x_1_5 = "\\Device\\winm32" wide //weight: 1
        $x_1_6 = "\\DosDevices\\emul65" wide //weight: 1
        $x_1_7 = "\\Device\\emul65" wide //weight: 1
        $x_1_8 = "\\DosDevices\\boot32" wide //weight: 1
        $x_1_9 = "\\Device\\boot32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

