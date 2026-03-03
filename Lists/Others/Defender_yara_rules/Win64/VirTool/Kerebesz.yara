rule VirTool_Win64_Kerebesz_A_2147964053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kerebesz.A"
        threat_id = "2147964053"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kerebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b ce 48 89 5c 24 48 48 89 5c 24 40 48 89 74 24 38 c7 44 24 30 01 00 00 00 c7 44 24 28 02 00 00 00 c7 44 24 20 01 00 00 00 ff ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 [0-32] e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 bc 24 18 01 00 00 ?? ?? ?? ?? ?? ?? ?? 41 b8 10 00 00 00 48 89 9c 24 10 01 00 00 48 8b c8 ff ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 [0-22] e8}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c0 33 d2 48 8b cf ff ?? ?? ?? ?? ?? 85 c0 [0-22] e8 ?? ?? ?? ?? 48 8b cf ff ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 3d 20 04 00 00 [0-22] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

