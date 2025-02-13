rule Worm_Win32_Narilam_A_2147650420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Narilam.A"
        threat_id = "2147650420"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Narilam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Max(raj) from Holiday_2" ascii //weight: 1
        $x_1_2 = {6c 73 73 61 73 2e 65 78 65 00 6d 61 6c 69 72 61 6e 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

