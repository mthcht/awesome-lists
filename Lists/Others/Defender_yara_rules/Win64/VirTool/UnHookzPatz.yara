rule VirTool_Win64_UnHookzPatz_A_2147839550_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/UnHookzPatz.A!MTB"
        threat_id = "2147839550"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "UnHookzPatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 85 f4 02 00 00 4c 8b 85 d8 02 00 00 48 8d ?? ?? ?? ?? ?? 48 8b 4c c5 50 ff 15 ?? ?? ?? ?? 89 85 b4 02 00 00 83 bd b4 02 00 00 00 7d 07}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 68 49 c6 45 69 89 c6 45 6a ca c6 45 6b b8 c6 45 6c bc c6 45 6d 00 c6 45 6e 00 c6 45 6f 00 c6 45 70 0f c6 45 71 05}  //weight: 1, accuracy: High
        $x_1_3 = {41 b8 40 00 00 00 ba 00 10 00 00 48 8b 8d b0 01 00 00 ff 15 ?? ?? ?? ?? 89 85 94 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 20 01 00 00 0f b6 00 3d e9 00 00 00 74 4c 48 8b 85 20 01 00 00 0f b6 40 03 3d e9 00 00 00 74 3a 48 8b 85 20 01 00 00 0f b6 40 08 3d e9 00 00 00 74 28 48 8b 85 20 01 00 00 0f b6 40 0a 3d e9 00 00 00 74 16 48 8b 85 20 01 00 00 0f b6 40 0c 3d e9 00 00 00 0f 85 8d 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

