rule VirTool_Win32_ExecutionFromADS_A_2147918745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExecutionFromADS.A"
        threat_id = "2147918745"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExecutionFromADS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 61 00 69 00 5f 00 61 00 6c 00 74 00 65 00 72 00 6e 00 61 00 74 00 65 00 5f 00 73 00 74 00 72 00 65 00 61 00 6d 00 5f 00 [0-32] 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

