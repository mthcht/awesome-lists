rule VirTool_Win64_LzDump_A_2147839547_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/LzDump.A!MTB"
        threat_id = "2147839547"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "LzDump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 45 28 00 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ba 08 00 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 85 c0 74 77 c7 45 64 04 00 00 00 48 8d ?? ?? 48 89 44 24 20 41 b9 04 00 00 00 4c 8d ?? ?? ba 14 00 00 00 48 8b 4d 28 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b f8 33 c0 b9 38 02 00 00 f3 aa c7 45 50 38 02 00 00 48 8d ?? ?? ?? ?? ?? 48 89 85 a8 02 00 00 48 8d ?? ?? 48 8b 4d 28 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 85 f8 00 00 00 00 00 00 00 c7 85 fc 00 00 00 00 00 00 00 c6 85 14 01 00 00 01 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? ba 20 00 00 00 48 8b c8 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 02 00 00 00 4c 8b 85 28 01 00 00 8b 55 64 48 8b 8d 68 01 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

