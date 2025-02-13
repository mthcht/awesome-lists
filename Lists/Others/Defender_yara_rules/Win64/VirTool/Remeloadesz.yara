rule VirTool_Win64_Remeloadesz_A_2147890413_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Remeloadesz.A!MTB"
        threat_id = "2147890413"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Remeloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 84 24 00 01 00 00 00 00 00 00 b8 08 00 00 00 48 6b c0 01 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 41 b8 01 00 00 00 ba 00 00 00 80 48 8b 8c 24 d8 01 00 00 48 8b 0c 01 ff 15 ?? ?? ?? ?? 48 89 44 24 68 48 83}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 84 24 08 01 00 00 00 00 00 00 48 8b 44 24 70 48 89 84 24 a8 00 00 00 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 4c 8d 8c ?? ?? ?? ?? ?? 45 33 c0 48 8d 94 ?? ?? ?? ?? ?? 48 8b 8c 24 f8 00 00 00 ff 94 ?? ?? ?? ?? ?? 89 44 24 60 ba 14 00 00 00 48 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 84 24 98 00 00 00 48 8b 84 24 98 00 00 00 48 89 84 24 a0 00 00 00 4c 8d 8c ?? ?? ?? ?? ?? 4c 8d 84 ?? ?? ?? ?? ?? ba ff ff 1f 00 48 8d 8c ?? ?? ?? ?? ?? ff 94 ?? ?? ?? ?? ?? 48 83 bc}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 04 24 83 f8 20 ?? ?? 0f b7 04 24 48 8b 4c 24 20 0f b6 04 01 83 f8 0f ?? ?? 0f b7 04 24 48 8b 4c 24 20 0f b6 44 01 01 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

