rule VirTool_Win64_InjregRatz_A_2147838742_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/InjregRatz.A!MTB"
        threat_id = "2147838742"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "InjregRatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 48 8b 45 f0 89 54 24 28 48 8b 55 10 48 89 54 24 20 41 b9 01 00 00 00 41 b8 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 48 8b 05 8f cd 0d 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 e0 c7 44 24 28 04 00 00 00 48 8d ?? ?? 48 89 54 24 20 41 b9 04 00 00 00 41 b8 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 48 8b 05 f0 cb 0d 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c2 48 8b 45 f0 89 54 24 28 48 8b 55 10 48 89 54 24 20 41 b9 01 00 00 00 41 b8 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 48 8b 05 2e ce 0d 00 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 c1 e8 ?? ?? ?? ?? 48 8d ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 48 8d ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 48 89 45 f8 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 45 f8 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_5 = {55 53 48 83 ec 78 48 8d ?? ?? ?? 48 89 4d 20 48 8d ?? ?? 4c 8b 45 20 48 8d ?? ?? ?? ?? ?? 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

