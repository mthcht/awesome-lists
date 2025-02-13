rule VirTool_Win64_Inzektor_A_2147836617_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Inzektor.A!MTB"
        threat_id = "2147836617"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Inzektor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b cd c7 44 24 28 00 00 00 00 45 33 c0 33 d2 48 89 74 24 20 48 8b cf ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {48 ff c3 80 3c 18 00 75 ?? 4c 8b cb 48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? ?? 48 8b d6 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {49 ff c0 42 80 3c 00 00 75 ?? 33 d2 c7 44 24 20 04 00 00 00 41 b9 00 30 00 00 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b8 04 01 00 00 48 8d 4c 24 6c 48 8b d7 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 48 8d ?? ?? ?? 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75 ?? 33 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

