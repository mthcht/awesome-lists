rule VirTool_Win64_Elevatekatz_A_2147953752_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Elevatekatz.A"
        threat_id = "2147953752"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Elevatekatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 18 57 48 81 ec 00 05 00 00 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 f0 04 00 00 48 8b da 48 8b f9 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 33 c4 48 89 44 24 38 41 b9 01 00 00 00 c6 44 24 30 cc ?? ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 48 8b da ff}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 6c 24 70 49 8b d6 48 89 44 24 20 49 8b cc ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

