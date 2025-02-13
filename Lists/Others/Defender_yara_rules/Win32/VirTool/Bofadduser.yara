rule VirTool_Win32_Bofadduser_A_2147901293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofadduser.A"
        threat_id = "2147901293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofadduser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Adding user failed" ascii //weight: 2
        $x_5_2 = "Adding Guest to the local machine" ascii //weight: 5
        $x_1_3 = "Adding user" ascii //weight: 1
        $x_1_4 = "#bofstop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

