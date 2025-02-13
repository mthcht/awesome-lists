rule VirTool_Win32_Fkeysteal_A_2147627620_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Fkeysteal.A"
        threat_id = "2147627620"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Fkeysteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "@*\\AC:\\Documents and Settings\\ZacK\\Desktop\\Zero\\Stub\\Project1.vbp" wide //weight: 10
        $x_10_2 = "Firefox Password Stealer FUD - Coded By: Zack" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

