rule TrojanDropper_Win64_NeedyMantis_A_2147978933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/NeedyMantis.A!dha"
        threat_id = "2147978933"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "NeedyMantis"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 5b 01 44 3b d1 48 8b d3 48 0f 4c d0 0f b6 [0-6] 41 30 43 ff 8b c3 44 3b d1 41 0f 4c c2 44 8d 50 01 48 8d 42 01 48 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 90 fe fe ff ff 30 50 02 0f b6 90 ff fe ff ff 0f b6 88 fc fe ff ff 30 50 03 30 08 0f b6 90 00 ff ff ff 0f b6 88 fd fe ff ff 30 50 04 30 48 01 48 8d 40 05 49 83 e8 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

