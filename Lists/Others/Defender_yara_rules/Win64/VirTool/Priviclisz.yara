rule VirTool_Win64_Priviclisz_A_2147847727_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Priviclisz.A!MTB"
        threat_id = "2147847727"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Priviclisz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 33 c9 ff 15 ?? ?? ?? ?? 4c 8b c0 44 8b cf 48 8d ?? ?? ?? ?? ?? b9 04 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 33 c9 ff 15 ?? ?? ?? ?? 48 89 5c 24 58 48 89 44 24 50 48 89 5c 24 48 48 89 5c 24 40 c7 44}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 d3 07 00 00 44 ?? ?? ?? 44 ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 05 a3 5d 00 00 48 85 c0 0f 84 dd 03 00 00 0f b7 c8 48 ?? ?? ?? 48 8b 4d 98 4c 8b 3c d1 4d 8b c7 48 8b d0 48 8d ?? ?? ?? ?? ?? e8 d1 ?? ?? ?? 4c 3b 7d b8 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b d7 48 8d ?? ?? ?? ?? ?? e8 08 ?? ?? ?? 49 83 e7 f1 4c 89 bd 08 02 00 00 48 89 b5 d0 01 00 00 4c 8d ?? ?? ?? ?? ?? ba 08 00 00 00 48 8b 0d 8b 55 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? ba 08 00 00 00 48 8b 0d 5a 55 00 00 ff 15 ?? ?? ?? ?? 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

