rule VirTool_Win64_Geiseresz_A_2147959255_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geiseresz.A"
        threat_id = "2147959255"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geiseresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 48 89 da ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 80 38 4c ?? ?? 80 78 01 8b ?? ?? 80 78 02 d1 ?? ?? 80 78 03 b8 ?? ?? 44 0f b7 78 04 66 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 10 44 24 30 0f 10 4c 24 40 ?? ?? ?? ?? ?? 41 0f 29 48 10 41 0f 29 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 10 44 24 30 0f 10 4c 24 40 ?? ?? ?? ?? ?? 41 0f 29 48 10 41 0f 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

