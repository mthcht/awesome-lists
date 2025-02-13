rule Backdoor_Win32_Sajdela_A_2147644339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sajdela.A"
        threat_id = "2147644339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sajdela"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 65 73 61 6a 20 64 65 20 6c 61 20 63 6c 69 65 6e 74 2e 20 54 6f 74 75 6c 20 65 20 4f 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 6f 63 65 73 73 20 4b 69 6c 6c 65 64 20 53 75 63 63 65 73 66 75 6c 6c 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 69 6c 65 73 20 73 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 6e 64 20 70 72 6f 63 65 73 73 65 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 61 62 62 79 00}  //weight: 1, accuracy: High
        $x_3_6 = {54 58 54 00 5c 63 73 72 6c 73 2e 64 6c 6c 00}  //weight: 3, accuracy: High
        $x_2_7 = {41 74 68 65 6e 65 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

