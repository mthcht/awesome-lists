rule TrojanProxy_Win32_Radds_A_2147691366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Radds.A"
        threat_id = "2147691366"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Radds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft__Sdk\\lib\\include\\cc1xm.js" ascii //weight: 1
        $x_1_2 = "\\Microsoft__Sdk\\lib\\include\\iexploror.exe" ascii //weight: 1
        $x_1_3 = "staRt \"ddsdsccss\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

