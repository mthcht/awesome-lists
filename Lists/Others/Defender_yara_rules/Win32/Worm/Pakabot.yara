rule Worm_Win32_Pakabot_2147600048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pakabot"
        threat_id = "2147600048"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pakabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "heh heh heh :kakap" ascii //weight: 3
        $x_1_2 = {68 02 20 00 00 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = {6a 00 6a 01 6a 00 6a 11 ff}  //weight: 2, accuracy: High
        $x_1_4 = {6a 00 6a 00 6a 00 6a 0d ff}  //weight: 1, accuracy: High
        $x_2_5 = {41 2d 9e 24 dd 44 64 4d 9b 6b d5 fd 76}  //weight: 2, accuracy: High
        $x_2_6 = {6a 00 6a 03 6a 2d 6a 11 ff}  //weight: 2, accuracy: High
        $x_1_7 = "SetClipboardData" ascii //weight: 1
        $x_1_8 = {6a 00 6a 00 6a 00 6a ff ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_5_9 = {8b 55 08 03 55 fc 8a 02 32 45 0c 8b 4d 08 03 4d fc 88 01 eb}  //weight: 5, accuracy: High
        $x_5_10 = {83 3d 40 01 80 7c 00 75}  //weight: 5, accuracy: High
        $x_5_11 = {a1 40 01 80 7c 85 c0 75}  //weight: 5, accuracy: High
        $x_6_12 = {6a 0a ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 6a 0a ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 2b (45 ??|85 ?? ??) 83 f8 0a 73 ?? 8b 8d ?? ?? ff ff 2b (4d ??|8d ?? ??) 83 f9 14 73}  //weight: 6, accuracy: Low
        $x_6_13 = {6a 0a 8b d8 ff d5 ff d7 6a 0a 8b f0 ff d5 ff d7 2b f3 5d 83 fe 0a 73 ?? 2b c3 83 f8 14 73}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

