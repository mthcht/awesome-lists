rule Backdoor_Win64_Spiderpig_A_2147777963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Spiderpig.A"
        threat_id = "2147777963"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Spiderpig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 [0-16] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-48] 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 70 69 64 [0-16] 65 78 65 00 6f 70 65 6e}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Spider-Rat\\Client\\" ascii //weight: 1
        $x_1_3 = "Hardware\\Description\\System\\CentralProcessor\\0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

