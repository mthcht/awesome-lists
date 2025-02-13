rule VirTool_Win64_Primasz_A_2147850169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Primasz.A!MTB"
        threat_id = "2147850169"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Primasz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 e8 ?? ?? ?? ?? 48 89 85 c8 00 00 00 48 c7 45 00 00 04 00 00 48 8d ?? ?? ?? ?? ?? 48 89 45 08 c6 85 87 00 00 00 00 48 8b 85 c8 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 88 85 87 00 00 00 80 bd 87 00 00 00 00 0f 85 ef 00 00 00 48 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 20 48 8b 54 24 38 41 b8 40 00 00 00 b8 04 00 00 00 44 0f 44 c0 48 03 1d 85 4e 03 00 48 89 4b 08 49 89 d9 48 89 53 10 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 10 48 8d ?? ?? ?? ?? ?? 48 8b 45 b8 49 89 d1 41 b8 40 00 00 00 ba 06 00 00 00 48 89 c1 41 ?? ?? 89 85 2c ff ff ff c6 85 2b ff ff ff 00 8b 85 2c ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

