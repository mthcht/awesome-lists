rule VirTool_Win64_Lamsys_A_2147929110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Lamsys.A"
        threat_id = "2147929110"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Lamsys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 4d 33 c9 4d 33 d2 89 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 8b d1 33 c9 41 8d 0a 83 f9 00 ?? ?? eb 0a 49 ff c0 4d 33 c8 4d 85 c8 ?? 3b c1 ?? ?? ff c0 ?? ?? eb f6 4d 33 c9 89 ?? ?? ?? ?? ?? 4c 8b c2 4c ?? ?? ?? ?? ?? ?? 50 58 48 33 c0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 33 d2 48 8b c1 4c 8b d0 33 c0 3b ?? ?? ?? ?? ?? 74 11 ff c0 eb f4 33 c0 48 33 c9 49 c1 e2 02 49 c1 e0 02 ff 25 39 3a 00 00 4d 33 d2 4c 89 15 2f 3a 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

