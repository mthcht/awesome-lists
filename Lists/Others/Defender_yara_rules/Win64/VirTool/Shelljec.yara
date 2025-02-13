rule VirTool_Win64_Shelljec_A_2147841300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelljec.A!MTB"
        threat_id = "2147841300"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelljec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 44 8b c3 33 d2 b9 ff ff 1f 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 c8 00 00 00 48 8b cf ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 74 24 50 4c 8d ?? ?? ?? ?? ?? 33 f6 41 b9 c8 00 00 00 48 8b d3 48 89 74 24 20 48 8b cf ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 74 24 30 4c 8b cb 89 74 24 28 45 33 c0 33 d2 48 89 74 24 20 48 8b cf ff}  //weight: 1, accuracy: High
        $x_1_5 = {ba ff ff ff ff 48 8b ce ff 15 ?? ?? ?? ?? 48 8b 0d a3 29 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

