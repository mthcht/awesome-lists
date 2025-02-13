rule Backdoor_Win32_Shell_D_2147651023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shell.D"
        threat_id = "2147651023"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ab 6a 11 33 c0 59 8d 7d ac f3 ab a1}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8d 7d f0 6a 11 ab ab ab ab 59 33 c0 8d 7d ac f3 ab}  //weight: 1, accuracy: High
        $x_2_3 = {50 c7 45 ac 44 00 00 00 c7 45 d8 01 01 00 00 66 89 45 dc 89 45 bc 89 45 c0 ff}  //weight: 2, accuracy: High
        $x_1_4 = "bG9nb258" ascii //weight: 1
        $x_1_5 = {73 64 6a 32 62 2e 33 33 32 32 2e 6f 72 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

