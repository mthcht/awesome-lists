rule TrojanSpy_Win32_Binal_A_2147696416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Binal.A"
        threat_id = "2147696416"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Binal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 8a 5c 30 ff 8b c3 04 d8 3c 57 77 0a 83 e0 7f 0f}  //weight: 10, accuracy: High
        $x_10_2 = {8a 12 80 ea 41 8d 14 92 8d 14 92 8b 4d ?? 8a 49 01 80 e9 41 02 d1 8b ce 2a d1 8b cf 2a d1}  //weight: 10, accuracy: Low
        $x_1_3 = {66 81 3b 4d 5a 0f 85 ?? ?? 00 00 [0-64] 81 3f 50 45 00 00 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

