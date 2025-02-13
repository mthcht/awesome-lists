rule TrojanDropper_Win32_Safadrew_A_2147610773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Safadrew.A"
        threat_id = "2147610773"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Safadrew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_13_1 = {8b c3 50 53 58 5b 83 c0 40 b8 00 00 00 00 b8 02 00 00 00 b9 05 00 00 00 83 c0 03}  //weight: 13, accuracy: High
        $x_4_2 = {b8 00 20 40 00 ff 73 d0}  //weight: 4, accuracy: High
        $x_3_3 = {66 81 3a 4d 5a 74 ?? ff 73 d0}  //weight: 3, accuracy: Low
        $x_2_4 = {c1 c2 04 ff 73 (d0|fc)}  //weight: 2, accuracy: Low
        $x_3_5 = {8f 43 d0 80 74 01 ?? ?? ff 73 d0}  //weight: 3, accuracy: Low
        $x_3_6 = {8f 43 fc 80 74 01 ?? ?? ff 73 fc}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_13_*))) or
            (all of ($x*))
        )
}

