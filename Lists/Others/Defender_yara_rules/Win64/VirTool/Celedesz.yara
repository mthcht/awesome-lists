rule VirTool_Win64_Celedesz_A_2147968575_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Celedesz.A"
        threat_id = "2147968575"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Celedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ff c0 66 41 3b c3 ?? ?? 45 8b c4 41 8b c8 ?? ?? ?? ?? ?? ?? ?? 48 03 cf e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 83 c6 04 49 83 c6 02 85 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 45 33 c0 ba 00 00 00 80 ff ?? ?? ?? ?? ?? 48 8b f0 48 83 f8 ff ?? ?? ?? ?? ?? ?? 33 d2 48 8b c8 ff ?? ?? ?? ?? ?? 44 8b f0 ff ?? ?? ?? ?? ?? 48 8b c8 45 8b c6 33 d2 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

