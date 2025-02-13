rule VirTool_Win64_Godfez_A_2147838153_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Godfez.A!MTB"
        threat_id = "2147838153"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Godfez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 81 ec 88 02 00 00 48 89 ac 24 80 02 00 00 48 8d ?? ?? ?? ?? ?? ?? 48 89 9c 24 98 02 00 00 48 89 84 24 ?? 02 00 00 b8 02 00 00 00 31 db e8 bb}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 44 24 68 48 8b 1d bd 6e 0d 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? bf 01 00 00 00 48 89 fe ?? e8 fb ?? ?? ?? 48 8d ?? ?? ?? ?? ?? bb 09 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 0f 11 7c 24 50 48 8d ?? ?? ?? ?? ?? 48 89 54 24 50 4c 8d ?? ?? ?? ?? ?? 4c 89 44 24 58 48 8b 1d 6a 6d 0d 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? bf 01 00 00 00 48 89 fe e8 a9 ?? ?? ?? b8 ff 0f 1f 00 31 db 8b 4c 24 2c e8 79}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 54 24 30 48 89 10 48 c7 40 08 00 00 00 00 48 8b 54 24 38 48 89 50 10 48 c7 40 18 02 00 00 00 44 0f 11 78 20 48 c7 40 30 00 00 00 00 48 8b 15 0d 6c 0d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

