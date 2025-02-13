rule TrojanClicker_Win32_Cutwail_A_2147601816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Cutwail.A"
        threat_id = "2147601816"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Click Verification" ascii //weight: 1
        $x_1_2 = "linkprob" ascii //weight: 1
        $x_1_3 = "log_filter_url" ascii //weight: 1
        $x_1_4 = "\\\\.\\Runtime" ascii //weight: 1
        $x_1_5 = "216.195.55.10" ascii //weight: 1
        $x_1_6 = {3d 45 57 59 42 59 75 01 46 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

