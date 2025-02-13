rule VirTool_Win64_Shelenjesz_A_2147909554_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelenjesz.A!MTB"
        threat_id = "2147909554"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelenjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 48 98 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f0 48 8b 45 f0 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 89 45 ec 48 8b 45 18 48 83 c0 08 48 8b 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 54 24 30 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 48 89 ca 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 c0 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 8b 45 fc 41 89 c0 ba 00 00 00 00 b9 ff ff 1f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4d d8 48 8b 45 c0 48 8b 55 f0 49 89 c8 48 89 c1 ?? ?? ?? ?? ?? 48 c7 45 b0 00 00 00 00 48 8b 55 b8 48 8b 45 e0 48 c7 44 24 48 00 00 00 00 ?? ?? ?? ?? 48 89 4c 24 40 48 c7 44 24 38 00 00 00 00 48 89 54 24 30 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

