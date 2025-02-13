rule VirTool_Win64_Tknmp_2147788405_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Tknmp!MTB"
        threat_id = "2147788405"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tknmp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 88 01 00 00 48 8b 80 b8 00 00 00 48 89 c3 48 8b 9b ?? 02 00 00 48 81 eb ?? 02 00 00 48 8b 8b e8 02 00 00 48 83 f9 04 75 e5 48 8b 8b ?? 03 00 00 80 e1 f0 48 89 88 ?? 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

