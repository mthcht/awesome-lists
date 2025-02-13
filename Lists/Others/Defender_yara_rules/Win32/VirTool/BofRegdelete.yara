rule VirTool_Win32_BofRegdelete_A_2147904126_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BofRegdelete.A"
        threat_id = "2147904126"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BofRegdelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegDeleteKeyValueA" ascii //weight: 1
        $x_1_2 = "BOF_TEST" ascii //weight: 1
        $x_1_3 = "Deleting registry key" ascii //weight: 1
        $x_1_4 = "delete_regkey failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

