rule Backdoor_Win32_Febian_A_2147706122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Febian.A"
        threat_id = "2147706122"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Febian"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 3a 5c 6d 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\bfconfig.txt" ascii //weight: 1
        $x_2_3 = "BianFengBackDoorV" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

