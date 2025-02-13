rule VirTool_Win32_DcomExecCommand_2147769994_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DcomExecCommand"
        threat_id = "2147769994"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DcomExecCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-8] 2f 00 51 00 20 00 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = "1 > \\\\127.0.0.1\\ADMIN$\\_" wide //weight: 1
        $x_1_3 = "2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

