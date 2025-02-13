rule Backdoor_Win32_Onklew_A_2147697217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Onklew.A"
        threat_id = "2147697217"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Onklew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OnlyOneKew" ascii //weight: 1
        $x_1_2 = "RunUrlKew" ascii //weight: 1
        $x_1_3 = "dnsck.housf.net" ascii //weight: 1
        $x_1_4 = {47 53 4e 61 6d 65 3d [0-12] 53 79 73 3d [0-12] 50 63 4e 61 6d 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

