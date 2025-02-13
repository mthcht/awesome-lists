rule VirTool_Win64_Remetecez_A_2147901809_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Remetecez.A!MTB"
        threat_id = "2147901809"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Remetecez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 5a 00 00 00 48 89 4c 24 20 ?? ?? ?? ?? ?? ?? ?? 48 8b cf 48 8b d0 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 83 bd 20 04 00 00 5a ?? ?? ?? ?? ?? ?? 48 8b 54 24 30 ?? ?? ?? ?? ?? ?? ?? 48 83 c2 5a 48 89 9d 20 04 00 00 41 b9 71 00 00 00 48 89}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 55 b8 48 89 55 d0 c7 44 24 28 04 00 00 00 89 54 24 20 ?? ?? ?? ?? 0f 29 4d 20 c7 44 24 70 68 00 00 00 66 0f 7f 45 80 66 0f 7f 45 c0 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b9 10 00 00 00 4c 8b c6 48 89 44 24 20 49 8b d4 48 8b cf ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 83 bd 20 04 00 00 10 ?? ?? 48 8b 06 41 bf 01 00 00 00 48 89 05 e6 3b 00 00 48 8b ?? ?? ?? ?? ?? 48 89 05 fe 3b 00 00 4c 89 25 c7 3b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Remetecez_B_2147901811_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Remetecez.B!MTB"
        threat_id = "2147901811"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Remetecez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 55 54 58 66 83 e4 f0 50 6a 60 5a 68 63 6d 64 00 54 59 48 29 d4 65 48 8b 32 48 8b 76 18 48 8b 76 10 48 ad 48 8b 30 48 8b 7e 30 03 57 3c 8b 5c 17 28 8b 74 1f 20 48 01 fe 8b 54 1f 24}  //weight: 1, accuracy: High
        $x_1_2 = {48 bb bb bb bb bb bb bb bb bb 48 b9 cc cc cc cc cc cc cc cc 48 89 0b 48 83 ec 50 48 89 d9 48 c7 c2 00 04 00 00 41 b8 02 00 00 00 ?? ?? ?? ?? ?? 48 b8 bb bb bb bb bb bb bb bb ?? ?? ?? ?? ?? ?? ?? 48 83 c4 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

