rule VirTool_Win64_Privilosz_A_2147847726_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Privilosz.A!MTB"
        threat_id = "2147847726"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Privilosz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c7 44 24 40 30 01 00 00 8d ?? ?? ff 15 ?? ?? ?? ?? 48 ?? ?? ?? ?? bf ff ff ff ff 48 8b c8 48 8b d8 ff 15 ?? ?? ?? ?? 85 c0 74 5e 48 ?? ?? ?? ?? 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d8 48 85 c0 0f 84 49 01 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8 48 85 c0 0f 84 31 01 00 00 0f 57 c0 48 89 5d 58 33 c0 48 c7 45 38 12 12 12 12 48 89}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d6 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 4c 89 7c 24 68 48 ?? ?? ?? ff 15 ?? ?? ?? ?? 48 ?? ?? ?? c7 45 a0 30 00 00 00 0f 57 c0 48 89}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 5c 24 68 48 8d ?? ?? ?? ?? ?? 48 8b c3 48 8b fb 8b d0 e8 ?? ?? ?? ?? b9 00 01 00 00 ff 15 ?? ?? ?? ?? 4c 8b f8 48 8b ce 33 c0 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

