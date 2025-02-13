rule VirTool_Win64_Disedr_A_2147930830_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Disedr.A"
        threat_id = "2147930830"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Disedr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7c 24 38 ?? ?? ?? ?? ?? 48 89 44 24 20 45 33 c0 4c 89 64 24 50 48 c7 c1 02 00 00 80 ff 15 3f 1c 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 65 10 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b 45 10 48 89 45 f0 ff ?? ?? ?? ?? ?? 8b c0 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b c0 ?? ?? ?? ?? 48 31 45 f0 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 03 c3 4c 89 64 24 30 48 d1 e8 4d 8b c6 44 0f b7 cd ba a4 00 09 00 44 89 64 24 28 49 8b cf 4c 89 64 24 20 66 45 89 64 46 10 ff ?? ?? ?? ?? ?? 8b d8 ff ?? ?? ?? ?? ?? 4d 8b c6 33 d2 48 8b c8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

