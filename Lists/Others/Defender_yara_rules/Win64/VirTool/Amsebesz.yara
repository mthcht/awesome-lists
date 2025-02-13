rule VirTool_Win64_Amsebesz_A_2147848727_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amsebesz.A!MTB"
        threat_id = "2147848727"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amsebesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 48 8d 94 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b f0 48 8d 94 ?? ?? ?? ?? ?? 0f b6 8c 24 00 01 00 00 84 c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 84 24 98 00 00 00 48 8d 84 ?? ?? ?? ?? ?? 48 89 44 24 20 45 ?? ?? ?? 4c 8d 84 ?? ?? ?? ?? ?? 48 8d 94 ?? ?? ?? ?? ?? 49 8b ce ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 7c 24 20 41 b9 01 00 00 00 4c 8d 84 ?? ?? ?? ?? ?? 48 8b d0 49 8b ce ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 0c cb ff 15 ?? ?? ?? ?? 44 8b c0 33 d2 8d ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

