rule VirTool_Win64_Rapotz_A_2147844662_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rapotz.A!MTB"
        threat_id = "2147844662"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rapotz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 85 e0 01 00 00 45 33 ff 48 c7 c7 ff ff ff ff 4c 89 7c 24 40 48 8b f7 e8}  //weight: 1, accuracy: High
        $x_1_2 = {b9 08 02 00 00 48 89 45 c8 0f 11 45 a8 48 89 45 80 0f 11 45 b8 0f 11 44 24 70 e8}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 7c 24 60 48 8d ?? ?? ?? 48 8b cb f3 0f 7f 44 24 50 ff 15 ?? ?? ?? ?? 85 c0 75 3e}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 89 7c 24 38 48 8d ?? ?? ?? 48 89 44 24 30 4c 8d ?? ?? 44 89 7c 24 28 41 b9 18 00 00 00 ba ac 00 09 00 4c 89 7c 24 20 49 8b ce ff 15 ?? ?? ?? ?? 85 c0 74 18}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 54 24 40 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 4c 24 40 e8 ?? ?? ?? ?? 48 8b f0 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

