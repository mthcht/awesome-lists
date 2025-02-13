rule TrojanDropper_Win32_Vasnasea_A_2147649879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vasnasea.A"
        threat_id = "2147649879"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vasnasea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {ba 02 02 02 02 39 54 03 fc 75 07 83 e9 01 8b e8 74 08 40 8d 70 fc 3b f7 72 eb 8d 44 24 18}  //weight: 8, accuracy: High
        $x_8_2 = {75 0d 8b 47 0c 03 45 08 03 c3 80 30 2a eb 39}  //weight: 8, accuracy: High
        $x_4_3 = {8b 4f 0c 03 4d 08 80 3c 19 c3 74 11 83 f8 03 75 10 8b 4f 0c 03 4d 08 80 3c 19 c2}  //weight: 4, accuracy: High
        $x_2_4 = "897234kjdsf4523234.com" ascii //weight: 2
        $x_2_5 = "\\\\.\\pipe\\mspipe_og" ascii //weight: 2
        $x_2_6 = "dao7erms_a" ascii //weight: 2
        $x_4_7 = {89 46 14 80 fa 3c 74 21 8b 46 14 83 c0 ff 78 07 3b c7 7d 03 89 46 14 8b 46 14}  //weight: 4, accuracy: High
        $x_4_8 = {c6 04 08 e9 8b 13 8b ce 2b c8 83 e9 05 89 4c 02 01 8d 4d fc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 3 of ($x_4_*))) or
            ((2 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

