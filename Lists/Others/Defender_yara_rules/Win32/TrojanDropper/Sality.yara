rule TrojanDropper_Win32_Sality_AU_2147636659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sality.AU"
        threat_id = "2147636659"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 00}  //weight: 10, accuracy: High
        $x_10_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 00}  //weight: 10, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 63 64 65 69 6e 61 61 2e 63 6f 6d 2f 73 6d 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {51 68 00 14 01 00 68 10 40 00 10 8b 95 fc fb ff ff 52 ff 15 1c 30 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

