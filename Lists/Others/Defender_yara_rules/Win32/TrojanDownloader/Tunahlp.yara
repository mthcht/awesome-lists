rule TrojanDownloader_Win32_Tunahlp_A_2147648826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tunahlp.A"
        threat_id = "2147648826"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tunahlp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 44 24 44 08 5d cf 76 81 44 24 30 08 5d cf 76 81 44 24 38 08 5d cf 76 81 44 24 24 08 5d cf 76}  //weight: 5, accuracy: High
        $x_1_2 = {09 3e 4d ce a5 34 bf 73 7e 6e 7d e6 74 79 c0 6a}  //weight: 1, accuracy: High
        $x_1_3 = {25 00 88 c3 71 26 ba 3b c2 4d eb 1c 20 64 54 9c}  //weight: 1, accuracy: High
        $x_1_4 = {b0 d6 3e 38 b1 1b 8a f7 cc 8d 40 77 4a 41 e8 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

