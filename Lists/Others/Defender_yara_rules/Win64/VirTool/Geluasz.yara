rule VirTool_Win64_Geluasz_A_2147967985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geluasz.A"
        threat_id = "2147967985"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geluasz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b ce 8b d7 48 8b cd 45 1b c0 41 f7 d8 41 ff c8 e8 ?? ?? ?? ?? 33 d2 8b d8 ?? ?? ?? e8 ?? ?? ?? ?? 8b d6 48 8b cd e8}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b c0 4c 8b cb 48 8b d7 48 8b ce e8 ?? ?? ?? ?? bb 01 00 00 00 85 c0 ?? ?? 44 8b c3 33 d2 48 8b ce e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

