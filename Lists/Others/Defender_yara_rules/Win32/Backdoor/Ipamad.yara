rule Backdoor_Win32_Ipamad_A_2147592628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ipamad.A"
        threat_id = "2147592628"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ipamad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DamipTrojan" ascii //weight: 1
        $x_1_2 = {74 33 62 31 00 53 63 72 65 65 6e 00 64 74 72 6a 77 5f 73 63 72 77 00 31 30 30 30 30}  //weight: 1, accuracy: High
        $x_1_3 = {62 63 6f 6e 6e 00 62 63 6c 73 00 73 73 74 61 74 00 74 32 62 31 00 74 32 62 32 00 74 34 62 38 00 65 69 70 00 65 70 6f 72 74 00 65 70 61 73 73 00 43 6f 6e 6e 65 63 74 69 6e 67}  //weight: 1, accuracy: High
        $x_1_4 = {4b 65 79 6c 6f 67 67 65 72 00 74 32 73 31 00 53 74 61 72 74 00 74 32 65 31 00 44 72 69 76 65 73}  //weight: 1, accuracy: High
        $x_1_5 = {74 31 62 31 00 4c 69 73 74 65 6e 20 70 6f 72 74 20 3a}  //weight: 1, accuracy: High
        $x_1_6 = {43 72 65 61 74 65 20 53 65 72 76 65 72 00 62 74 73 72 76 00 43 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

