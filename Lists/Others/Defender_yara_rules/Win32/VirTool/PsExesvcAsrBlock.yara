rule VirTool_Win32_PsExesvcAsrBlock_A_2147915054_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PsExesvcAsrBlock.A"
        threat_id = "2147915054"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PsExesvcAsrBlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 70 00 73 00 65 00 78 00 65 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

