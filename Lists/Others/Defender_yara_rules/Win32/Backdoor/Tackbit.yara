rule Backdoor_Win32_Tackbit_B_2147722846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tackbit.B!bit"
        threat_id = "2147722846"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tackbit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {65 7a 72 65 61 6c [0-16] 73 70 61 63 65 [0-16] 6c 69 6e 65 2d 63 6c 69 65 6e 74}  //weight: 2, accuracy: Low
        $x_2_2 = {53 79 73 49 6e 66 6f [0-16] 42 61 74 63 68 43 6f 6d 6d 61 6e 64 [0-16] 4c 6f 63 61 6c 55 70 64 61 74 65 [0-16] 49 6e 73 74 61 6c 6c [0-16] 55 6e 69 6e 73 74 61 6c 6c [0-16] 50 69 6e 67}  //weight: 2, accuracy: Low
        $x_1_3 = {00 46 69 6c 65 53 70 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4b 65 79 4c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

