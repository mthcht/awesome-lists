rule VirTool_Win64_Encryfer_A_2147928572_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Encryfer.A"
        threat_id = "2147928572"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Encryfer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c6 66 c7 00 08 00 c6 40 02 27 0f b6 07 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 49 89 c7 4c 89 a4 24 d0 02 00 00 66 c7 00 00 05 c6 40 02 69 0f b6 07 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 66 c7 00 00 0c 48 89 44 24 30 c6 40 02 29 0f b6 07 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 49 89 c4 66 c7 00 00 1c c6 40 02 14 0f b6 07 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c6 66 c7 00 00 50 c6 40 02 56 0f b6 07 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 48 89 fb 48 89 c7 66 c7 00 00 1c c6 40 02 42 0f b6 03 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 49 89 c5 66 c7 00 00 16 c6 40 02 3e 0f b6 03 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 66 c7 00 0a 00 c6 40 02 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

