rule Worm_Win32_Selfish_2147657910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Selfish"
        threat_id = "2147657910"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Selfish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 45 f8 66 c7 45 ec 08 00 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 83 7d 08 00 74 05 8b 55 08 eb 05 ba}  //weight: 1, accuracy: High
        $x_1_2 = {83 3d e0 95 4f 00 00 74 08 8b 15 e0 95 4f 00 eb 03 8d 57 1b 52 6a 00 e8 3f 3c 0e 00}  //weight: 1, accuracy: High
        $x_1_3 = {56 69 72 75 73 55 6e 69 74 00}  //weight: 1, accuracy: High
        $x_3_4 = {23 31 00 00 00 4d 5a 00 00}  //weight: 3, accuracy: High
        $x_3_5 = {49 4e 46 41 43 54 00}  //weight: 3, accuracy: High
        $x_3_6 = {57 48 45 52 45 20 64 61 74 65 3d 43 55 52 44 41 54 45 28 29 00 55 50 44 41 54 45 20 63 6f 6e 66 69 67}  //weight: 3, accuracy: High
        $x_3_7 = "(siteid,ip,date) VALUES" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

