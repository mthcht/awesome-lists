rule Backdoor_Win32_Dodiw_A_2147696785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dodiw.A"
        threat_id = "2147696785"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dodiw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DoS Active..." wide //weight: 1
        $x_1_2 = "File Downloaded and Executed" wide //weight: 1
        $x_1_3 = "Babylon RAT Client" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

