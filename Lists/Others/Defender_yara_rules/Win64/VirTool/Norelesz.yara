rule VirTool_Win64_Norelesz_A_2147976036_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Norelesz.A"
        threat_id = "2147976036"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Norelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b cd 41 b9 01 00 00 00 49 0f 42 c8 0f b6 04 0b ?? ?? ?? ?? 30 04 16 48 8b c5 49 83 f8 20 49 0f 42 c0 0f b6 04 03 30 44 16 01 ?? ?? ?? ?? 49 83 f8 20 4c 0f 42 c8 49 83 f9 20}  //weight: 1, accuracy: Low
        $x_1_2 = {45 8b c6 49 8b d7 48 8b ce e8 ?? ?? ?? ?? 85 c0 ?? ?? ff ?? ?? ?? ?? ?? ba 08 00 00 00 41 b8 08 02 00 00 48 8b c8 ff ?? ?? ?? ?? ?? 48 8b f8 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

