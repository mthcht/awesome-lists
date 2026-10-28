rule VirTool_Win64_Bypetesz_A_2147981115_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypetesz.A"
        threat_id = "2147981115"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 c0 01 48 3d 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3d [0-17] f6 05}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 38 41 83 c7 01 48 83 c0 08 48 39 c8 ?? ?? 48 8b 84 24 a8 00 00 00 49 89 c8 48 01 c2 49 29 c0 49 39 d0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 30 00 00 00 48 89 da ff ?? 48 85 c0 ?? ?? 48 8b 94 24 ?? 00 00 00 48 8b 8c 24 a8 00 00 00 48 01 d1 4c 39 ac 24 b0 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

