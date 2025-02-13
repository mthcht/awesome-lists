rule VirTool_Win32_Codienece_A_2147767615_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Codienece.A!MTB"
        threat_id = "2147767615"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Codienece"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 58 48 89 6c 24 50 48 8d ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 84 00 48 8b 05 02 ff 1c 00 48 8b 0d 7b 61 10 00 48 89 04 24 0f 57 c0 0f 11 44 24 08 48 89 4c 24 18 48 8b 44 24 60 48 89 44 24 20 0f 11 44 24 28 e8 76 07 00 00 48 8b 44 24 38 48 85 c0 74 1f 48 8b 0d dd fe 1c 00 48 89 0c 24 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b 6c 24 50 48 83 c4 58 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 84 24 98 00 00 00 84 00 48 8d 88 10 03 00 00 48 89 8c 24 a0 00 00 00 48 89 0c 24 e8 75 94 fd ff 48 8b 44 24 48 48 8b 8c 24 98 00 00 00 48 89 81 18 03 00 00 48 8b 84 24 a0 00 00 00 48 89 04 24 e8 40 96 fd ff 0f 57 c0 0f 11 44 24 68 0f 11 44 24 78 0f 11 84 24 88 00 00 00 48 8b 05 a4 fb 1c 00 48 89 04 24 48 8d 44 24 68 48 89 44 24 08 48 8d 44 24 68 48 89 44 24 10 48 c7 44 24 18 30 00 00 00 e8 de 03 00 00 48 83 7c 24 20 00 0f 84 eb 00 00 00 48 8b 44 24 70 48 8d 88 00 40 00 00 48 89 4c 24 50 65 48 8b 14 25 28 00 00 00 48 8b 92 00 00 00 00 48 8b 5a 08 48 89 5c 24 60 48 39 d9 77 32 48 29 cb 48 81 fb 00 00 00 04 77 26 48 89 0a 48 05 80 53 00 00 48 89 42 10 48 89 42 18 e8 a1 f5 02 00 48 8b ac 24 a8 00 00 00 48 81 c4 b0 00 00 00 c3}  //weight: 1, accuracy: High
        $x_1_3 = {65 48 8b 0c 25 28 00 00 00 48 8b 89 00 00 00 00 48 3b 61 10 76 36 48 83 ec 18 48 89 6c 24 10 48 8d ?? ?? ?? e8 f7 fd ff ff 48 8d ?? ?? ?? ?? ?? 48 89 04 24 48 c7 44 24 08 13 00 00 00 e8 5e f9 ff ff 48 8b 6c 24 10 48 83 c4 18 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {65 48 8b 0c 25 28 00 00 00 48 8b 89 00 00 00 00 48 3b 61 10 0f 86 35 01 00 00 48 83 ec 40 48 89 6c 24 38 48 8d ?? ?? ?? 48 8b 44 24 50 48 89 04 24 48 8b 44 24 58 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b 44 24 10 48 8b 4c 24 18 48 8b 54 24 30 48 8b 5c 24 28 48 85 db 0f 84 dc 00 00 00 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

