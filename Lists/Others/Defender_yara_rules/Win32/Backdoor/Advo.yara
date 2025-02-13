rule Backdoor_Win32_Advo_2147630779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Advo"
        threat_id = "2147630779"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Advo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 69 64 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 60 33 c0 cd 2e}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 e1 6d c6 45 e2 73 c6 45 e3 61 c6 45 e4 63 c6 45 e5 6d c6 45 e6 33 c6 45 e7 32 c6 45 e8 2e c6 45 e9 64 c6 45 ea 72 c6 45 eb 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

