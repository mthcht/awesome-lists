rule VirTool_Win64_Peledesz_A_2147980265_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Peledesz.A"
        threat_id = "2147980265"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Peledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 00 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 e0 ?? ?? ?? ?? ?? ?? ?? 48 89 45 e8 c7 45 00 00 00 00 00 c7 45 d4 40 00 00 00 ?? ?? ?? ?? 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 e8 [0-17] 48 8b ?? ?? ?? ?? ?? 48 89 c1 e8 [0-17] 41 b8 04 01 00 00 48 89 c2 b9 00 00 00 00 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

