rule VirTool_Win32_SuspLummaInj_B_2147974822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.B"
        threat_id = "2147974822"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 0c 37 83 f8 5c 74 05 83 f8 2f 75 08 c6 44 0c 37 00 49 eb ?? 6a 5c 57 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {f2 0f 10 05 ?? ?? ?? ?? 0f 11 00 0f 57 c0 0f 11 44 24 0c 0f 11 04 24 89 f1 6a 00 6a 14 50 68 03 20 01 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 40 04 01 00 00 00 89 e2 83 22 00 89 f1 52 6a 10 50 68 1f 20 01 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {83 60 04 00 c7 00 59 01 00 00 8d 4c 24 04 83 21 00 6a 00 68 00 00 00 08 6a 40 50 6a 00 6a 0e 51 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

