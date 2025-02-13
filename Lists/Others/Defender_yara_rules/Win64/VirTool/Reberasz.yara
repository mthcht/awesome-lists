rule VirTool_Win64_Reberasz_A_2147906324_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Reberasz.A!MTB"
        threat_id = "2147906324"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Reberasz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 [0-16] 8b d0 [0-18] 4c 8b 0d 2a 40 00 00 ?? ?? ?? ?? ?? 48 89 44 24 28 ?? ?? ?? ?? ?? ?? ?? ba 00 10 00 00 89 7c 24 20 33 c9 89 7c 24 30 ?? ?? ?? ?? ?? ?? b9 e8 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 58 12 00 14 00 48 89 44 24 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 c7 45 b8 30 00 00 00 48 89 45 c8 ?? ?? ?? ?? ?? ?? ?? 48 8b 44 24 38 0f 57 c0 45 33 c9 48 89 45 c0 ba 00 00 00 10 48 c7 45 d0 40 00 00 00 f3 0f 7f 45 d8 48 89 7c 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

