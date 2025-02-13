rule VirTool_Win64_Nodlhokz_A_2147844664_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nodlhokz.A!MTB"
        threat_id = "2147844664"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nodlhokz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 50 18 48 03 d2 49 8b 0c d1 48 89 48 10 49 8b 4c d1 08 48 89 48 18}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 ef be ad de 48 8d ?? ?? ?? ?? ?? 33 c9 ff ?? 48 8d ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {49 c1 e0 04 4c 03 ?? ?? ?? ?? ?? 4d 8b 08 4d 8b 40 08 48 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8b c6 48 8b d5 8b cb ff}  //weight: 1, accuracy: High
        $x_1_5 = {48 c1 e7 05 ff 15 ?? ?? ?? ?? 4c 8b ?? ?? ?? ?? ?? 4c 8b cf 48 8b c8 33 d2 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

