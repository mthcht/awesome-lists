rule VirTool_Win64_Defendkilz_A_2147808495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Defendkilz.A!MTB"
        threat_id = "2147808495"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Defendkilz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 45 bb 02 00 00 00 c7 45 b7 0c 00 00 00 ff 15 ?? ?? ?? ?? 48 8b c8 4c 8d ?? ?? 49 8b d6 41 ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b c8 4c 8d ?? ?? 45 33 c0 ba ff 01 0f 00 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 65 8f 4c 89 65 ef 4c 89 6d 97 4c 89 6d a7 48 c7 45 af 07 00 00 00 41 b8 15 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? 49 8b cc e8 ?? ?? ?? ?? 84 c0 ?? ?? 41 bd 01 00 00 00 ?? ?? ?? ?? ?? 41 b8 ff 01 0f 00 48 8d ?? ?? ?? ?? ?? 48 8b ce ff 15 ?? ?? ?? ?? 48 8b d8 48 89 45 cf 41 bd 01 00 00 00 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 6b 64 69 72 [0-7] 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73}  //weight: 1, accuracy: Low
        $x_1_4 = {63 6f 70 79 [0-7] 2e 5c [0-7] 2e 73 79 73 [0-7] 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 [0-30] 2e 73 79 73 [0-7] 2f 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

