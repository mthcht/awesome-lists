rule VirTool_Win32_kangiz_A_2147788331_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/kangiz.A"
        threat_id = "2147788331"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "kangiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 51 83 65 f8 00 56 8b f1 6a 04 52 8b 06 89 45 fc 8d ?? ?? 50 6a 00 8d ?? ?? 50 6a ff ff 15 ?? ?? ?? ?? 85 c0 78 13 8b 45 fc 8b 4d f8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0a ff 75 a8 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 88 8d 01 00 00 8d ?? ?? c7 45 dc 0c 00 00 00 89 45 c0 33 c9 8d ?? ?? c7 45 e0 02 00 00 00 50 6a 01 51 8d ?? ?? 66 89 4d e4 50 68 ff 01 0f 00 ff 75 fc c7 45 ac 18 00 00 00 89 4d b0 89 4d b8 89 4d b4 89 4d bc ff 15 ?? ?? ?? ?? 8b f0}  //weight: 1, accuracy: Low
        $x_1_3 = {50 51 51 68 20 00 00 04 51 51 51 57 8d ?? ?? ?? ?? ?? 50 ff 75 f8 ff 15 ?? ?? ?? ?? 85 c0 74 32 68 10 27 00 00 ff 75 c4 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
        $x_1_5 = {50 68 10 b5 40 00 68 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 75 59 85 ff 74 11 56 ff 75 fc ff 15 ?? ?? ?? ?? f7 d8 1b db 43}  //weight: 1, accuracy: Low
        $x_1_6 = {66 89 45 c8 8d ?? ?? 50 8d ?? ?? 89 75 c4 50 a1 ?? ?? ?? ?? 83 c0 3c 50 33 c0 50 68 00 04 08 00 50 50 50 ff 75 f4 50 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_7 = {57 ff 75 f4 6a 40 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 5d 8d ?? ?? 50 57 56 6a 16 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

