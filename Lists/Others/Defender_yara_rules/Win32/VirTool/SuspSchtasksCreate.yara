rule VirTool_Win32_SuspSchtasksCreate_A_2147805815_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspSchtasksCreate.A"
        threat_id = "2147805815"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSchtasksCreate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 [0-8] 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 2f 00 52 00 55 00 20 00 [0-8] 53 00 59 00 53 00 54 00 45 00 4d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 2f 00 54 00 52 00 20 00 [0-8] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

