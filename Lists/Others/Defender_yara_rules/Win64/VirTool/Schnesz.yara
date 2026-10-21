rule VirTool_Win64_Schnesz_A_2147980693_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Schnesz.A"
        threat_id = "2147980693"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Schnesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 30 e8 ?? ?? ?? ?? 41 b9 40 00 00 00 41 b8 00 30 00 00 ba fb 07 00 00 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff ?? 48 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 8b 05 [0-17] 41 89 d9 49 89 d0 89 c2 e8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 49 89 c0 ba 00 00 00 00 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

