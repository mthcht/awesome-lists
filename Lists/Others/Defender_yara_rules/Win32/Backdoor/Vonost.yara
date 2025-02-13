rule Backdoor_Win32_Vonost_A_2147672251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vonost.A"
        threat_id = "2147672251"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 85 cb 00 00 00 68 c6 85 cc 00 00 00 2d c6 85 cd 00 00 00 63 c6 85 ce 00 00 00 6e c6 85 cf 00 00 00 0d}  //weight: 5, accuracy: High
        $x_5_2 = {7c 58 69 61 6e 43 68 65 6e 67 44 65 6c 61 79 7c 00}  //weight: 5, accuracy: High
        $x_5_3 = {7c 47 65 74 5a 68 75 61 6e 67 54 61 69 7c 00}  //weight: 5, accuracy: High
        $x_1_4 = {73 76 6f 6e 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {7a 68 75 64 6f 6e 67 66 61 6e 67 79 75 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

