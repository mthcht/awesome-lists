rule Backdoor_Win32_Ocivat_A_2147687826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ocivat.A"
        threat_id = "2147687826"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ocivat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 50 57 53 52 9c 66 f7 e2 3b d6 66 c1 c2 0d 66 03 d9 66 69 c0 d3 18 c0 ed 1e b8 87 83 bf db 03 c0 76 0b 77 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 00 54 00 4c 00 4d 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_2_3 = {50 72 6f 78 79 2d 41 75 74 68 65 6e 74 69 63 61 74 65 3a 20 42 41 53 49 43 00 00 00 2e 76 76 74 00 00 00 00 2e 69 6e 69 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

