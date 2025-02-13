rule VirTool_Win64_EpreLoad_A_2147903671_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/EpreLoad.A"
        threat_id = "2147903671"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EpreLoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 4c 8b d1 b8 48 0f 45 d5 ?? ?? ?? ?? ?? 81 3f 4c 8b d1 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d3 48 0f 45 d5 ?? ?? ?? ?? ?? 81 3e 4c 8b d1 b8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 0f 45 dd 48 8b d3 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 83 c4 20 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

