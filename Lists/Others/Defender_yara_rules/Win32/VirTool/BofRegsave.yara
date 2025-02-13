rule VirTool_Win32_BofRegsave_A_2147901297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BofRegsave.A"
        threat_id = "2147901297"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BofRegsave"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegOpenKeyExA failed" ascii //weight: 1
        $x_1_2 = "RegDeleteKeyValueA failed" ascii //weight: 1
        $x_1_3 = "BOF_TEST" ascii //weight: 1
        $x_1_4 = "Deleting registry key" ascii //weight: 1
        $x_1_5 = "delete_regkey failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

