rule Backdoor_Win32_Eayla_A_2147652423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Eayla.A"
        threat_id = "2147652423"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Eayla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 61 76 65 72 20 76 73 20 61 6c 79 61 65 2c 44 65 66 65 61 74 65 64 20 70 69 6c 6c 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 68 69 74 20 69 73 20 61 6c 79 61 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 ec 4e c6 45 ed 56 c6 45 ee 43 c6 45 ef 41 c6 45 f0 67 c6 45 f1 65 c6 45 f2 6e c6 45 f3 74 c6 45 f4 2e c6 45 f5 6e c6 45 f6 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

