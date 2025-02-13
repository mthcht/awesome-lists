rule VirTool_Win64_Shadowdump_A_2147926328_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shadowdump.A"
        threat_id = "2147926328"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shadowdump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 b9 20 02 bc 03 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b d1 b8 26 00 00 00 0f 05 c3 4c 8b d1 b8 0f 00 00 00 0f 05 c3 4c 8b d1 b8 55 00 00 00 0f 05 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

