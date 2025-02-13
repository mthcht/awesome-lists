rule VirTool_Win64_Promesesz_A_2147892464_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Promesesz.A!MTB"
        threat_id = "2147892464"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Promesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7c 24 50 48 8d ?? ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b f8 48 ?? ?? ?? 48 83 f9 fd ?? ?? 33 c0 4c 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b cb ff 15 ?? ?? ?? ?? 40 84 ff ?? ?? 48 8d ?? ?? ?? ?? ?? 4c 39}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b cb ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 89 74 24 30 89 74 24 28 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 c0 48 8d ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 48 89 7c 24 20 45 33 d2 48 8d ?? ?? ?? ?? ?? 4c 8b d9 48 bf 00 00 a2 a8 aa 2a 02 00 48 be 00 00 a6 ed ff 7f d6 71 48 bd 55 55 55 55 05 00 00 00 45 8d}  //weight: 1, accuracy: Low
        $x_1_5 = {41 b9 30 00 01 00 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b d8 48 ff c8 48 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

