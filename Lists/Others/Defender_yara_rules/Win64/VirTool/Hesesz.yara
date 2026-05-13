rule VirTool_Win64_Hesesz_A_2147969161_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hesesz.A"
        threat_id = "2147969161"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hesesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 20 ?? ?? ?? ?? 41 b9 06 00 00 00 48 89 c1 48 89 f2 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? c7 45 30 00 00 00 00 c7 45 e4 00 00 00 00 44 8b 45 24 ?? ?? ?? ?? ba 06 00 00 00 48 89 f1 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 45 ec 40 40 c7 45 e8 40 40 40 40 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 89 c6 48 85 c0 [0-19] 48 89 e9 41 b8 0e 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

