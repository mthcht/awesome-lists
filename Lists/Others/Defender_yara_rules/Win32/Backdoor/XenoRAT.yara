rule Backdoor_Win32_XenoRAT_ARR_2147957106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/XenoRAT.ARR!MTB"
        threat_id = "2147957106"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<CreateSubSocket>d__7" ascii //weight: 2
        $x_3_2 = "<RunClientLoopAsync>d__8" ascii //weight: 3
        $x_5_3 = "F72771C08CD4D9E6D5E023D03DA3C9" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

