rule TrojanDropper_Win32_Derusbi_C_2147693984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Derusbi.C!dha"
        threat_id = "2147693984"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 0e 88 19 41 4f 75 f7 bf e4 01 00 00 8b ca 03 c7 03 d7 8a 1c 31 80 f3 30 88 19 41 4f}  //weight: 2, accuracy: High
        $x_1_2 = {25 73 5c 25 64 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 73 71 6c 73 72 76 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 5c 73 71 6c 73 72 76 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

