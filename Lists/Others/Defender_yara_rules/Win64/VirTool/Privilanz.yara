rule VirTool_Win64_Privilanz_A_2147847415_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Privilanz.A!MTB"
        threat_id = "2147847415"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Privilanz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 9c 24 f0 0a 00 00 48 89 44 24 30 33 d2 48 8d ?? ?? ?? 48 89 bc 24 f8 0a 00 00 48 89 44 24 28 4c 8b ce 8b 44 24 50 33 c9 44 8d ?? ?? 89 44 24 20 4c 89 b4 24 00 0b 00 00 ff 15 ?? ?? ?? ?? 33 ff 39 7c 24 54}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 03 00 00 00 48 89 44 24 48 4c 8d ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 c7 44 24 30 00 00 00 00 48 89 44 24 40 41 b9 14 80 00 00 48 8d ?? ?? ?? ?? ?? ?? ba 02 00 00 00 48 89 44 24 38 33 c9 48 8d ?? ?? ?? ?? ?? 48 89 44 24 28 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b d2 41 81 f0 6e 74 65 6c 41 81 f2 69 6e 65 49 44 8b cb 8b f0 33 c9 41 ?? ?? ?? 45 0b d0 0f a2 41 81 f1}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c9 48 89 44 24 28 45 8d ?? ?? c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? ?? 8b 54 24 50 b9 40 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f0 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

