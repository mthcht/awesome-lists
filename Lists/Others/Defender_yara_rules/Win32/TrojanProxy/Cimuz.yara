rule TrojanProxy_Win32_Cimuz_G_2147803804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Cimuz.G"
        threat_id = "2147803804"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://58.65.239.82" ascii //weight: 1
        $x_1_2 = "mcafee" ascii //weight: 1
        $x_1_3 = "Kaspersky" ascii //weight: 1
        $x_1_4 = "symantec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

