rule VirTool_Win64_Hebesz_A_2147969159_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hebesz.A"
        threat_id = "2147969159"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c7 4c 89 b5 b8 04 00 00 [0-17] 41 b8 0e 00 00 00 e8 ?? ?? ?? ?? 4c 8b 6d b0 4c 89 e8 48 f7 d8 ?? ?? ?? ?? ?? ?? 4c 8b 75 b8 48 8b 5d c0 48 89 f9 4c 89 f2 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 f8 48 b8 fe ff 00 00 ff ff ff ff 48 23 45 20 48 ff c0 48 89 45 20 48 c7 45 18 00 00 00 00 ?? ?? ?? ?? 48 c7 c1 fe ff ff ff e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {55 56 48 83 ec 68 ?? ?? ?? ?? ?? 48 c7 45 00 fe ff ff ff 48 8b 11 31 c0 81 3a 04 00 00 80 ?? ?? 80 3d [0-17] 48 83 c2 10 4c 8b 02 4c 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

