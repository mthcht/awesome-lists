rule VirTool_Win64_Chemonesz_A_2147917410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Chemonesz.A!MTB"
        threat_id = "2147917410"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Chemonesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 89 4d 10 48 89 55 18 [0-134] b8 00 00 00 00 48 83 c4 20 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 e0 48 8b 40 50 48 8b 55 18 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 18 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 e0 66 89 50 48 48 8b 45 18 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 e0 66 89 50 4a c6 45 ef 01}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 45 d8 48 8b 45 d8 48 8b 40 50 48 8b 55 10 48 89 c1 ?? ?? ?? ?? ?? 48 85 c0 0f 95 c0 84 c0 ?? ?? 48 8b 45 d8 0f b7 40 48 0f b7 d0 48 8b 45 d8 48 8b 40 50 49 89 d0 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 d8 66 c7 40 48 00 00 48 8b 45 d8 66 c7 40 4a 00 00 b8 01 00 00 00 ?? ?? 48 8b 45 c0 48 8b 00 48 89 45 c0 83 45 fc 01}  //weight: 1, accuracy: Low
        $x_1_4 = {55 48 89 e5 48 83 ec 60 48 89 4d 10 48 89 55 18 c7 45 dc 60 00 00 00 8b 45 dc 65 48 8b 00 48 89 45 d0 48 8b 45 d0 48 89 45 f0 48 8b 45 f0 48 8b 40 18 48 8b 40 20 48 89 45 c8 c6 45 ef 00 c7 45 fc 00 00 00 00 80 7d ef 00 ?? ?? ?? ?? ?? ?? 83 7d fc 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

