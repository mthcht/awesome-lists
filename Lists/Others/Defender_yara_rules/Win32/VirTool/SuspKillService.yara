rule VirTool_Win32_SuspKillService_C_2147938496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspKillService.C"
        threat_id = "2147938496"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspKillService"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 75 00 6c 00 20 00 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 [0-24] 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 75 6c 20 26 20 6e 65 74 20 73 74 6f 70 [0-24] 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

