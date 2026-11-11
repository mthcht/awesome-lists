rule VirTool_Win64_Steledesz_A_2147981849_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Steledesz.A"
        threat_id = "2147981849"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Steledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b ce 4c 8b c5 48 89 44 24 20 48 8b d7 48 8b cb ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 40 00 00 00 33 d2 41 b9 00 30 00 00 49 8b f0 48 8b d9 ff ?? ?? ?? ?? ?? 48 8b f8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b cf 48 89 44 24 30 45 33 c0 89 44 24 28 33 d2 48 8b cb 48 89 44 24 20 ff ?? ?? ?? ?? ?? 48 8b f0 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

