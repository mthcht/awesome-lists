rule VirTool_Win32_BofScconfig_A_2147901299_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BofScconfig.A"
        threat_id = "2147901299"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BofScconfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BOF_SVC_NAME" ascii //weight: 1
        $x_1_2 = "lpcszHostName" ascii //weight: 1
        $x_1_3 = "lpcszServiceName" ascii //weight: 1
        $x_1_4 = "config_service failed" ascii //weight: 1
        $x_1_5 = "Argument domain " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

