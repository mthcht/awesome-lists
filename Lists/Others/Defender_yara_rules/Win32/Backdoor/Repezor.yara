rule Backdoor_Win32_Repezor_A_2147684969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Repezor.A"
        threat_id = "2147684969"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Repezor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 3a 5c 73 74 6f 72 61 67 65 5c 63 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 63 5f 70 6c 75 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {01 05 00 00 74 ?? 81 7d ?? 02 05 00 00 74 ?? eb ?? 81 7d ?? 01 06 00 00 74 ?? 81 7d ?? 02 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Repezor_B_2147684970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Repezor.B"
        threat_id = "2147684970"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Repezor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 3a 5c 73 74 6f 72 61 67 65 5c 63 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 63 5f 70 6c 75 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {01 05 00 00 74 ?? 81 7d ?? 02 05 00 00 74 ?? eb ?? 81 7d ?? 01 06 00 00 74 ?? 81 7d ?? 02 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

