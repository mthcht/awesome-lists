rule VirTool_Win32_Bofenableuser_A_2147901290_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofenableuser.A"
        threat_id = "2147901290"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofenableuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Guest" ascii //weight: 1
        $x_1_2 = "Account was disabled, attempting to enable" ascii //weight: 1
        $x_1_3 = "Account should be enabled" ascii //weight: 1
        $x_1_4 = "EnableUser failed" ascii //weight: 1
        $x_1_5 = "bofstop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

