rule Backdoor_Win32_Dalgan_B_2147682888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dalgan.B"
        threat_id = "2147682888"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalgan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%tmp%\\~alot.dat" ascii //weight: 1
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 79 73 49 6e 74 65 72 6e 61 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "ail: %s:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

