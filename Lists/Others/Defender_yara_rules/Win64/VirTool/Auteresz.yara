rule VirTool_Win64_Auteresz_A_2147978289_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Auteresz.A"
        threat_id = "2147978289"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Auteresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 ba 02 00 00 00 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 c7 45 a8 00 00 00 00 48 8b 8d 28 02 00 00 ?? ?? ?? ?? ba 02 00 00 00 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 4d a8 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8d 28 02 00 00 48 8b ?? ?? ?? ?? ?? ff ?? 48 8b 4d a8 ff ?? 48 89 f1 ff ?? 48 c7 45 a8 00 00 00 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 89 c6 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 b0 00 00 00 3d 8a 01 00 c0 ?? ?? 3d 0d 00 00 c0 ?? ?? ?? ?? ?? ?? 3d 5e 00 00 c0 [0-19] ba 45 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

