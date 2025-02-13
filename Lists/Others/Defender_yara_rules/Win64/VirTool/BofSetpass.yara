rule VirTool_Win64_BofSetpass_A_2147901303_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BofSetpass.A"
        threat_id = "2147901303"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BofSetpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unable to set user password" ascii //weight: 1
        $x_1_2 = "User password should have been set" ascii //weight: 1
        $x_1_3 = "Setting password" ascii //weight: 1
        $x_1_4 = "setuserpass failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

