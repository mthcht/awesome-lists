rule VirTool_Win64_Phantogesz_A_2147917412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Phantogesz.A!MTB"
        threat_id = "2147917412"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Phantogesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4d 10 [0-22] 48 89 45 f0 48 8b 45 f0 48 8b 55 10 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 e8 48 8b 45 e8 48 89 45 e0 c7 45 fc 00 00 00 00 83 7d fc 1f ?? ?? 8b 45 fc 48 98 48 8b 55 e0 48 01 d0 0f b6 00 3c 0f ?? ?? 8b 45 fc 48 98 ?? ?? ?? ?? 48 8b 45 e0 48 01 d0 0f b6 00 3c 05}  //weight: 1, accuracy: Low
        $x_1_2 = {49 89 d1 41 b8 04 00 00 00 ba 0a 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c0 0f 95 c0 84 c0 ?? ?? 48 8b 45 f8 c6 00 b8 48 8b 45 f8 48 83 c0 01 8b 55 10 89 10 48 8b 45 f8 48 83 c0 05 c6 00 0f 48 8b 45 f8 48 83 c0 06 c6 00 05 48 8b 45 f8 48 83 c0 07 c6 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 02 00 00 00 b9 04 00 00 00 ?? ?? ?? ?? ?? 89 c2 ?? ?? ?? ?? ?? ?? ?? 41 89 d0 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 [0-18] 48 89 c1 ?? ?? ?? ?? ?? 83 f0 01 84 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 8c 04 00 00 39 85 44 07 00 00 ?? ?? 8b 85 88 04 00 00 41 89 c0 ba 00 00 00 00 b9 ff 03 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 48 07 00 00 48 83 bd 48 07 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {55 53 48 81 ec d8 07 00 00 [0-19] c7 85 44 07 00 00 48 06 00 00 [0-18] 89 85 40 07 00 00 [0-18] 89 85 3c 07 00 00 [0-25] 48 89 c1 8b 85 40 07 00 00 89 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

