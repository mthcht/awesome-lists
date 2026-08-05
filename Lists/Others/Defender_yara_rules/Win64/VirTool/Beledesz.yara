rule VirTool_Win64_Beledesz_A_2147975260_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Beledesz.A"
        threat_id = "2147975260"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Beledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 08 48 8b 44 24 08 0f b6 00 83 f8 4c ?? ?? 48 8b 44 24 08 0f b6 40 01 3d 8b 00 00 00 ?? ?? 48 8b 44 24 08 0f b6 40 02 3d d1 00 00 00 ?? ?? 48 8b 44 24 08 0f b6 40 03 3d b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 54 24 10 48 89 4c 24 08 57 48 81 ec 00 01 00 00 48 8b 84 24 10 01 00 00 48 83 38 00 ?? ?? 48 8b 84 24 10 01 00 00 83 78 08 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

