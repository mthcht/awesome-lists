rule VirTool_Win64_Minidumpesz_A_2147910768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Minidumpesz.A!MTB"
        threat_id = "2147910768"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Minidumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 60 c7 45 fc 34 02 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 10 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f0 48 83 7d f0 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 41 89 c0 ba 01 00 00 00 b9 ff ff 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 e8 48 83 7d e8 00 [0-17] 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? b9 ff ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 fc 48 8b 4d f0 48 8b 45 e8 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 02 00 00 00 49 89 c8 48 89 c1 ?? ?? ?? ?? ?? 89 45 e4 83 7d e4 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

