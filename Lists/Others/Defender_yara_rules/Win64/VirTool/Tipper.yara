rule VirTool_Win64_Tipper_A_2147811856_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Tipper.A!MTB"
        threat_id = "2147811856"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 57 56 53 83 ec ?? 8b 5c 24 54 8b 74 24 58 c7 44 24 2c 00 00 00 00 85 db 0f 94 c2 85 f6 0f 94 c0 08 c2 0f 85 bf 00 00 00 8b 44 24 50 85 c0 0f 84 b3 00 00 00 89 1c 24 e8 ?? ?? ?? ?? 89 c5 85 c0 0f 84 a1 00 00 00 8b 44 24 50 c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 74 24 08 c7 44 24 04 00 00 00 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ?? ?? 89 c7 85 c0 74 6f 89 44 24 04 8b 44 24 50 c7 44 24 10 00 00 00 00 89 74 24 0c 89 5c 24 08 89 04 24 ff 15 ?? ?? ?? ?? 83 ec ?? 85 c0 74 47 8d ?? ?? ?? 8d ?? ?? c7 44 24 14 00 00 00 00 89 44 24 18 8b 44 24 5c 89 54 24 0c 89 44 24 10 8b 44 24 50 c7 44 24 08 00 00 10 00 c7 44 24 04 00 00 00 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ec 1c eb 08}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 24 a1 ?? ?? ?? ?? 89 c6 f3 a6 0f 97 c2 80 da 00 84 d2 0f ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 44 24 34 8b 44 24 24 8d ?? ?? a1 ?? ?? ?? ?? 89 44 24 38 ff d0 89 7c 24 30 89 7c 24 08 bf ?? ?? ?? ?? c7 44 24 04 00 00 00 00 89 04 24 ff 15 ?? ?? ?? ?? b9 00 01 00 00 89 c6 31 c0 83 ec 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 34 c7 44 24 04 00 00 00 00 c7 04 24 3a 04 00 00 89 44 24 08 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 ec 0c 85 c0 0f 84 ?? ?? ?? ?? 8b 4c 24 30 c7 44 24 0c 00 00 00 00 89 74 24 04 89 4c 24 08 89 04 24 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 ec 10 85 c0 0f 84 ?? ?? ?? ?? c7 44 24 04 ff ff ff ff 89 04 24 ff 15 ?? ?? ?? ?? 83 ec 08 8b 44 24 34}  //weight: 1, accuracy: Low
        $x_1_4 = {57 56 53 83 ec 20 e8 ?? ?? ?? ?? c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

