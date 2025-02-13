rule VirTool_Win64_Oveloadesz_A_2147894335_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Oveloadesz.A!MTB"
        threat_id = "2147894335"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Oveloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 68 4c ?? ?? ?? ?? 48 89 74 24 28 41 b9 10 00 00 00 33 d2 48 89 44 24 74 48 8b cb c7 44 24 70 01 00 00 00 c7 44 24 7c 02 00 00 00 48 89 74 24 20 ff 15 ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
        $x_1_2 = {48 33 c4 48 89 84 24 80 00 00 00 33 f6 48 89 74 24 40 ff 15 ?? ?? ?? ?? 48 8b c8 4c ?? ?? ?? ?? 8d ?? ?? ff 15 ?? ?? ?? ?? 48 8b 5c 24 40 4c ?? ?? ?? ?? 48 8d 15}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b c0 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 45 33 c9 48 89 74 24 30 89 74 24 28 48 8d ?? ?? ?? ?? ?? ba 00 00 00 40 48 89 7c 24 48 89 74 24 50 45 ?? ?? ?? c7 44 24 20 03 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

