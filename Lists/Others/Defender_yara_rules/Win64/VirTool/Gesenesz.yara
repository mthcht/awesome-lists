rule VirTool_Win64_Gesenesz_A_2147959640_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gesenesz.A"
        threat_id = "2147959640"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gesenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c7 44 38 24 38 ?? ?? 48 85 f6 ?? ?? 48 85 ff ?? ?? 4d 8b c4 48 85 f6 ?? ?? 33 d2 49 8b c0 48 f7 f7 0f b6 44 14 48 41 30 04 28 49 ff c0 4c 3b c6}  //weight: 1, accuracy: Low
        $x_1_2 = {41 c1 e0 06 44 0b c2 41 83 eb 06 ?? ?? 48 3b ce ?? ?? 41 8b c0 c1 f8 10 88 04 29 48 ff c1 48 3b ce ?? ?? 41 8b c0 c1 f8 08 88 04 29 48 ff c1 48 3b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

