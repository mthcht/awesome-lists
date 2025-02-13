rule Backdoor_Win32_Weniavera_A_2147690749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Weniavera.A"
        threat_id = "2147690749"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Weniavera"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {65 78 65 20 2f 63 20 00}  //weight: 5, accuracy: High
        $x_1_2 = {57 45 4e 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 2e 2e 3b 3b 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 2e 2e 2e 7c 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 2e 2e 24 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 2e 2e 2e 3f 2f 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {21 21 2c 40 2c 5f 28 29 5b 5d 2e 2e 3b 21 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 bb 01 00 00 89 84 24 98 00 00 00 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

