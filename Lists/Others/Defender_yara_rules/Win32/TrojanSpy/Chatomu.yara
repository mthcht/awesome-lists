rule TrojanSpy_Win32_Chatomu_A_2147709228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Chatomu.A"
        threat_id = "2147709228"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chatomu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Moutcha\\" wide //weight: 1
        $x_1_2 = {72 00 65 00 63 00 64 00 74 00 2e 00 77 00 61 00 76 00 22 00 00 00 00 00 2a 00 00 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 52 00 65 00 63 00 66 00 69 00 6c 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 00 6c 00 6f 00 67 00 67 00 65 00 72 00 79 00 [0-16] 74 00 6c 00 6f 00 67 00 67 00 65 00 72 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {44 00 77 00 6e 00 6c 00 64 00 46 00 69 00 6c 00 65 00 [0-16] 73 00 63 00 72 00 65 00 65 00 6e 00 [0-16] 73 00 73 00 73 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = {55 00 70 00 6c 00 64 00 46 00 69 00 6c 00 65 00 [0-16] 55 00 70 00 64 00 61 00 74 00 65 00 [0-16] 2e 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 77 00 2e 00 74 00 6d 00 70 00 [0-16] 63 00 61 00 6d 00 [0-16] 62 00 6c 00 6f 00 6b 00 7a 00 62 00 65 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

