rule VirTool_Win64_Remesz_A_2147959637_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Remesz.A"
        threat_id = "2147959637"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Remesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 c7 48 89 d3 [0-18] 41 b8 0a 00 00 00 4c 89 f1 e8 ?? ?? ?? ?? 48 8b 53 08 4c 8b 43 10 4c 89 f1 e8 ?? ?? ?? ?? 48 8b 97 e8 00 00 00 4c 8b 87 f0 00 00 00 4c 89 f1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c2 c1 ea 08 48 83 c1 fe 3d 00 01 00 00 89 d0 ?? ?? ?? ?? ?? ?? 31 c9 31 d2 ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 48 89 c1 31 c0 f0 48 0f b1 0d b5 ca 0a 00 ?? ?? ?? ?? ?? ?? 49 89 c7 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

