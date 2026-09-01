rule VirTool_Win64_Morebesz_A_2147977308_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Morebesz.A"
        threat_id = "2147977308"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Morebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 c7 44 24 24 1c 00 00 00 ?? ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 85 c0 [0-20] 4c 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {49 89 c4 48 89 c1 ff ?? ?? ?? ?? ?? 41 b8 d0 04 00 00 4c 89 f1 31 d2 e8 ?? ?? ?? ?? c7 44 24 70 10 00 10 00 4c 89 e1 4c 89 f2 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 ff ?? 48 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 f1 ff ?? 48 89 [0-18] ff ?? ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

