rule TrojanClicker_Win32_Monkif_A_2147621080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Monkif.A"
        threat_id = "2147621080"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 14 3e 83 c6 01 3b f1 7c d9}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 05 53 56 57 75 11 8b 75 0c e8}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 6e 66 69 67 2e 64 6c 6c 00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

