rule Backdoor_Win32_Polnur_A_2147650723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Polnur.A"
        threat_id = "2147650723"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Polnur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IntelController" ascii //weight: 1
        $x_1_2 = {4d 61 6e 61 67 65 72 5f 52 75 6e 5f 4c 6f 6f 70 00 00 00 00 45 78 70 5f 4f 6e 52 65 61 64}  //weight: 1, accuracy: High
        $x_1_3 = "~MHz" ascii //weight: 1
        $x_1_4 = "c_1102.nls" ascii //weight: 1
        $x_1_5 = {53 74 61 72 74 46 75 6e 00 00 00 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Polnur_C_2147650754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Polnur.C"
        threat_id = "2147650754"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Polnur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 74 24 10 8d 46 01 50 c6 06 7c e8}  //weight: 2, accuracy: High
        $x_2_2 = {3b fb 76 09 80 34 33 09 43 3b df 72 f7}  //weight: 2, accuracy: High
        $x_1_3 = {6a 01 56 c6 06 81 e8}  //weight: 1, accuracy: High
        $x_1_4 = {69 c0 0c 01 00 00 8d 44 30 14 50}  //weight: 1, accuracy: High
        $x_2_5 = {c6 45 f0 7b c6 45 f1 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

