rule Backdoor_Win32_Lisfel_B_2147663481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lisfel.B"
        threat_id = "2147663481"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisfel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 6d 3d 25 73 26 63 74 3d 25 64 26 69 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 4c 49 53 46 4c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 6c 63 6d 64 3a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 67 65 74 20 65 72 72 30 72 21 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Lisfel_C_2147663482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lisfel.C"
        threat_id = "2147663482"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisfel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 75 73 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 6c 75 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "wl-cmd\\Release\\dll1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

