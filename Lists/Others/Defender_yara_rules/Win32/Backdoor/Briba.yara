rule Backdoor_Win32_Briba_A_2147660508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Briba.A"
        threat_id = "2147660508"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Briba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loginmid=%s&nickid=0&s=%s" ascii //weight: 1
        $x_1_2 = "c0d0so0" ascii //weight: 1
        $x_1_3 = {80 3e 47 75 0c 80 7e 01 49 75 06 80 7e 02 46 74 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Briba_B_2147690112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Briba.B"
        threat_id = "2147690112"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Briba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%\"93;;dey2/2wur$u{" ascii //weight: 1
        $x_1_2 = {72 61 7a 6f 72 5f 2e 64 6c 6c 00 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 63 30 64 30 73 6f 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {80 3e 47 75 0c 80 7e 01 49 75 06 80 7e 02 46 74 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Briba_C_2147690113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Briba.C"
        threat_id = "2147690113"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Briba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 75 70 64 61 74 2e 64 6c 6c 00 52 65 70 6f 72 74 45 72 72 6f 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 74 3d 25 73 26 64 3d 25 64 26 6a 73 6f 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 74 3d 25 73 26 69 64 3d 25 64 26 73 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "%\"93;;dey2/2wur$u{" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

