rule Worm_Win32_Yoybot_2147600665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yoybot"
        threat_id = "2147600665"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoybot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = ".jpeg-www.imageshack.com" ascii //weight: 5
        $x_5_2 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d}  //weight: 5, accuracy: High
        $x_3_3 = "\\photo album." ascii //weight: 3
        $x_3_4 = "YO YO YO :" ascii //weight: 3
        $x_3_5 = {6a 2e 50 53 89 7c 24 ?? c7 44 24 ?? 50 4b 01 02 66 c7 44 24 ?? 14 00 66 89 ac 24 ?? 00 00 00 c7 84 24 ?? 00 00 00 20 00 00}  //weight: 3, accuracy: Low
        $x_3_6 = {50 4b 01 02 66 c7 45 ?? 14 00 66 c7 45 ?? 00 00 c7 45 ?? 20 00 00 00 8b f4 6a 00 8d 8d ?? ?? ff ff 51 6a 2e 8d 55 ?? 52 8b 45 ?? 50}  //weight: 3, accuracy: Low
        $x_2_7 = {69 6d 73 74 61 72 74 00}  //weight: 2, accuracy: High
        $x_2_8 = {00 69 6e 64 69 72 00}  //weight: 2, accuracy: High
        $x_1_9 = {64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_10 = {2e 7a 69 70 00}  //weight: 1, accuracy: High
        $x_1_11 = "SetClipboardData" ascii //weight: 1
        $x_5_12 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a 56 ff 15 ?? ?? ?? ?? 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3 56 56 56 6a 0d ff d3 6a 32}  //weight: 5, accuracy: Low
        $x_5_13 = {6a 00 6a 01 6a 00 6a 11 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 6a 00 6a 00 6a 00 8b fc 6a 56 ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 6a 00 6a 03 6a 2d 6a 11 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 6a 00 6a 00 6a 00 6a 0d ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 6a 32}  //weight: 5, accuracy: Low
        $x_5_14 = {6a 00 6a 01 6a 00 6a 11 ff d6 6a 00 6a 00 6a 00 6a 56 ff d3 50 ff d6 6a 00 6a 03 6a 2d 6a 11 ff d6 6a 00 6a 00 6a 00 6a 0d ff d6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

