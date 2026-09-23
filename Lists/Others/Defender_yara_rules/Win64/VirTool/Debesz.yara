rule VirTool_Win64_Debesz_A_2147978708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Debesz.A"
        threat_id = "2147978708"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Debesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 8b 05 ?? ?? ?? ?? 85 c0 ?? ?? b9 ff ff ff ff 48 8b ?? ?? ?? ?? ?? ff [0-16] 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 83 ec 50 ?? ?? ?? ?? ?? ?? ?? 41 b8 ac b6 7b ca ba b0 07 0b fe 48 89 c1 e8 ?? ?? ?? ?? 48 89 45 f8 48 83 7d f8 00 ?? ?? 48 c7 45 e8 00 00 00 00 48 c7 45 e0 00 10 00 00 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

