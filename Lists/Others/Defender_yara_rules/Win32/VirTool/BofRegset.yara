rule VirTool_Win32_BofRegset_A_2147901298_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BofRegset.A"
        threat_id = "2147901298"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BofRegset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Successfully set regkey" ascii //weight: 1
        $x_1_2 = "BOF_TEST" ascii //weight: 1
        $x_1_3 = "Setting registry key" ascii //weight: 1
        $x_1_4 = "set_regkey failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

