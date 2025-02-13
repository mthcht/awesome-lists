rule TrojanDropper_Win32_Phdet_A_2147644476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Phdet.A"
        threat_id = "2147644476"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 e9 68 05 ad 89 0d 6a 00 6a 01 c7 44 24}  //weight: 1, accuracy: High
        $x_1_2 = {7e 15 6a 7a 6a 61 e8 ?? ?? ?? ?? 83 c4 08 66 89 04 77 46 3b f3 7c eb}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 00 44 00 45 00 4c 00 00 00 00 00 45 00 72 00 72 00 6f 00 72 00 43 00 6f 00 6e 00 74 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

