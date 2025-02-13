rule Backdoor_Win32_Ecltys_A_2147656933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ecltys.A"
        threat_id = "2147656933"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ecltys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2f 63 6c 61 73 73 69 63 2f 61 63 6f 75 6e 74 2f 69 6d 61 67 65 2f 61 64 64 72 5f 6d 65 6d 62 65 72 2e 61 73 70}  //weight: 1, accuracy: High
        $x_1_2 = {00 5c 5c 2e 5c 70 69 70 65 5c 73 73 6e 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

