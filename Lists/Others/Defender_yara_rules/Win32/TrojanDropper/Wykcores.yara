rule TrojanDropper_Win32_Wykcores_A_2147643782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Wykcores.A"
        threat_id = "2147643782"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Wykcores"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 dc 8b 4d e0 8a 14 0a 8a 45 e0 2a d0 80 f2 17 02 d0 8b 45 dc 8b 4d e0 88 14 08 ff 45 e0 81 7d e0 00 04 00 00 75 d8}  //weight: 1, accuracy: High
        $x_1_2 = {80 38 2a 74 22 46 40 4a 75 f6 eb 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

