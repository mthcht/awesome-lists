rule Backdoor_Win64_Repezor_A_2147684971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Repezor.A"
        threat_id = "2147684971"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Repezor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 3a 5c 73 74 6f 72 61 67 65 5c 63 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 63 5f 70 6c 75 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {3d 01 05 00 00 7c ?? 3d 02 05 00 00 7e ?? 3d 00 06 00 00 74 ?? 3d 01 06 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 00 06 00 00 7f ?? 74 ?? 81 ea 00 05 00 00 74 ?? ff ca 74 ?? ff ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win64_Repezor_B_2147684972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Repezor.B"
        threat_id = "2147684972"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Repezor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 3a 5c 73 74 6f 72 61 67 65 5c 63 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 63 5f 70 6c 75 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {3d 01 05 00 00 7c ?? 3d 02 05 00 00 7e ?? 3d 00 06 00 00 74 ?? 3d 01 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

