rule PWS_Win64_WallStealer_CI_2147959426_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/WallStealer.CI!MTB"
        threat_id = "2147959426"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "WallStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SELECT Name FROM Win32_Processor" ascii //weight: 2
        $x_2_2 = "SELECT Name FROM Win32_VideoController" ascii //weight: 2
        $x_2_3 = "Chrome\\User Data" ascii //weight: 2
        $x_2_4 = "Edge\\User Data" ascii //weight: 2
        $x_2_5 = "Mozilla Firefox" ascii //weight: 2
        $x_2_6 = "Opera Stable" ascii //weight: 2
        $x_2_7 = "Brave-Browser\\User Data" ascii //weight: 2
        $x_2_8 = "loginusers" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

