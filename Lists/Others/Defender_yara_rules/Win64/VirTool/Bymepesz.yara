rule VirTool_Win64_Bymepesz_A_2147964049_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bymepesz.A"
        threat_id = "2147964049"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bymepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 57 48 83 ec 20 48 8b fa ff ?? ?? ?? ?? ?? 48 8b d8 ff ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 85 db ?? ?? 81 7f 20 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 ac 24 38 05 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 b4 24 40 05 00 00 b9 01 00 00 00 48 89 bc 24 20 05 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b f8 ff ?? ?? ?? ?? ?? 33 d2 b9 04 00 00 00 8b e8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

