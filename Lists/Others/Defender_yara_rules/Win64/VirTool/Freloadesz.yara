rule VirTool_Win64_Freloadesz_A_2147918045_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Freloadesz.A!MTB"
        threat_id = "2147918045"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Freloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 80 34 00 0a 48 ff c0 48 3d 16 01 00 00 ?? ?? 4c 89 74 24 20 41 b9 16 01 00 00 66 0f 6f c3 66 0f 73 d8 08 66 48 0f 7e c3 48 8b d3 66 48 0f 7e df 48 8b cf ?? ?? ?? ?? ?? ?? 4c 89 74 24 30 44 89 74 24 28 4c 89 74 24 20 4c 8b cb 45 33 c0 33 d2 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 56 18 49 03 d7 48 8b ca 48 d1 e9 48 8b 46 10 48 ff c8 48 23 c8 83 e2 01 48 8b 46 08 48 8b 0c c8 48 8b 3c d1 0f 57 c0 0f 11 45 ef 0f 11 45 ff 0f 11 45 0f 41 b9 30 00 00 00 ?? ?? ?? ?? 33 d2 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 46 08 48 8b 0c c8 48 8b 3c f9 48 89 7d c7 48 89 5d cf 48 8b cf ?? ?? ?? ?? ?? ?? 89 45 d7 ?? ?? ?? ?? 48 89 44 24 20 41 b9 40 00 00 00 41 b8 16 01 00 00 48 8b d3 48 8b cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

