rule Backdoor_Win32_Tosct_A_2147654358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tosct.A"
        threat_id = "2147654358"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tosct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 32 33 34 35 00 00 00 31 32 33 21 40 23 71 77 65 51 57 45}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 69 65 74 2e 65 78 65 00 00 00 25 73 5c 25 73 00 00 00 63 6d 64 2e 65 78 65 00 43 72 65 61 74 65 50 69 70 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

