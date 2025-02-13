rule VirTool_Win32_Patcher_C_2147642855_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Patcher.C"
        threat_id = "2147642855"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 83 c0 18 64 8b 08 89 e2 83 c0 18 8b 04 08 b9 02 00 00 00 0f b6 04 01 83 c0 17 03 02 ff e0 76 ?? 13 bb 64 c3 90 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 42 f6 8b 5a fa 8a 52 fe 31 c9 30 10 40 41 31 ca 39 d9 76 f6 59 58 8b 50 ea 89 11 8b 50 ee 89 51 04 58 9d ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

