rule VirTool_Win64_Refledumpesz_A_2147924244_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Refledumpesz.A!MTB"
        threat_id = "2147924244"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Refledumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b c3 33 d2 b9 ff ff 1f 00 ?? ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 [0-24] b9 88 13 00 00 [0-19] 48 89 44 24 40 4c 89 74 24 48 ?? ?? ?? ?? ?? 48 89 44 24 30 4c 89 74 24 28 4c 89 74 24 20 ?? ?? ?? ?? 45 33 c0 8b d3 48 8b cf ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c8 ff ?? ?? ?? ?? ?? 48 85 c0 [0-20] 0f 57 c0 0f 11 44 24 78 0f 11 45 88 ?? ?? ?? ?? ?? 48 89 4c 24 28 4c 89 74 24 20 45 33 c9 45 33 c0 ?? ?? ?? ?? 48 8b cb ?? ?? 8b f0 85 c0 ?? ?? ?? ?? ?? ?? 8b 5d 88}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 10 [0-16] 48 8b f8 48 83 f8 ff [0-38] 4c 89 74 24 20 ?? ?? ?? ?? 44 8b 05 f2 41 00 00 48 8b 15 f3 41 00 00 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_4 = {44 8b c3 33 d2 [0-33] 33 d2 48 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

