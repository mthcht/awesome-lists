rule VirTool_Win64_Delenjesz_A_2147977306_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Delenjesz.A"
        threat_id = "2147977306"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Delenjesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 6c 24 50 48 8b ce 48 89 7c 24 58 e8 ?? ?? ?? ?? 41 b9 00 30 00 00 c7 44 24 20 40 00 00 00 33 d2 48 8b cb ?? ?? ?? ?? ?? ?? ?? ?? 4c 8b c5 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b cd 48 c7 44 24 20 00 00 00 00 4c 8b c6 48 8b d7 48 8b cb ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 30 00 00 00 00 4c 8b c8 c7 44 24 28 00 00 00 00 45 33 c0 33 d2 48 89 7c 24 20 48 8b cb ff ?? ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

