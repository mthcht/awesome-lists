rule VirTool_Win32_ExecutionFromADS_B_2147937934_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExecutionFromADS.B"
        threat_id = "2147937934"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExecutionFromADS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 61 00 69 00 5f 00 61 00 6c 00 74 00 65 00 72 00 6e 00 61 00 74 00 65 00 5f 00 73 00 74 00 72 00 65 00 61 00 6d 00 5f 00 [0-32] 3a 00 61 00 69 00 2d 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

