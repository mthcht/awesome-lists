rule VirTool_Win32_SuspDeleteEventlog_A_2147805816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspDeleteEventlog.A"
        threat_id = "2147805816"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDeleteEventlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 [0-8] 20 00 63 00 6c 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 [0-8] 20 00 63 00 6c 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_3 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 [0-8] 20 00 63 00 6c 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

