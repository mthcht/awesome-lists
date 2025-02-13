rule PWS_Win64_Tukrina_A_2147724969_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Tukrina.A!dha"
        threat_id = "2147724969"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Tukrina"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 11 00 00 00 80 30 ?? 48 ff c0 48 83 e9 01 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 11 00 00 00 66 66 66 66 66 0f 1f 84 00 00 00 00 00 80 70 ff ?? 80 30 ?? 48 83 c0 02 48 83 e9 01 75 ef}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 13 00 00 00 0f 1f 80 00 00 00 00 80 30 ?? 48 ff c0 48 83 ea 01 75 f4}  //weight: 1, accuracy: Low
        $x_2_4 = {b8 6b 00 00 00 b9 65 00 00 00 66 41 89 43 ?? b8 72 00 00 00 c6 44 24 ?? 20 66 41 89 43 ?? b8 6e 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

