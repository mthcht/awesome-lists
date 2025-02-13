rule Backdoor_Win32_SofXdr_A_2147730258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SofXdr.A!MTB"
        threat_id = "2147730258"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SofXdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "results/?ags=_________&ags=_________&" ascii //weight: 1
        $x_1_2 = "C:\\INTERNAL\\REMOTE.EXE" wide //weight: 1
        $x_1_3 = "YbprSNSIsHMOtLkUwUZpWldlJKfTrZXgHN" ascii //weight: 1
        $x_1_4 = "is running" wide //weight: 1
        $x_1_5 = "is not running" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

