rule Backdoor_Win32_Odordahlia_A_2147957191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Odordahlia.A!dha"
        threat_id = "2147957191"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Odordahlia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 63 00 70 00 6c 00 00 00 00 00 00 00 62 00 61 00 74 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {00 00 63 00 6f 00 6d 00 00 00 00 00 00 00 73 00 63 00 72 00 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 00 5c 00 31 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 00 2f 00 67 00 72 00 61 00 6e 00 74 00 3a 00 72 00 20 00 45 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 28 00 4f 00 49 00 29 00 28 00 43 00 49 00 29 00 28 00 00 00}  //weight: 5, accuracy: High
        $x_5_5 = {00 00 3a 00 20 00 2f 00 66 00 73 00 3a 00 4e 00 54 00 46 00 53 00 20 00 2f 00 51 00 20 00 2f 00 59 00 00 00}  //weight: 5, accuracy: High
        $x_5_6 = {00 00 43 00 44 00 20 00 44 00 72 00 69 00 76 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 00 55 00 53 00 42 00 20 00 44 00 69 00 73 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Odordahlia_B_2147957192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Odordahlia.B!dha"
        threat_id = "2147957192"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Odordahlia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "final_sa" ascii //weight: 1
        $x_1_2 = "https_head" ascii //weight: 1
        $x_1_3 = "text_sem_name" ascii //weight: 1
        $x_1_4 = "oversecs" ascii //weight: 1
        $x_10_5 = {6a 02 58 c1 e0 03 6a ?? 59 66 89 4c 05 ?? 6a 02 58 c1 e0 00 6a ?? 59 66 89 4c 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

