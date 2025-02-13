rule VirTool_Win64_Shelpluk_A_2147817504_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelpluk.A!MTB"
        threat_id = "2147817504"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelpluk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 14 99 48 ff c3 48 3b d8 ?? ?? 48 8b 5c 24 30 48 8d ?? ?? ?? ?? ?? ?? 49 3b c1 ?? ?? 0f 1f 00 30 14 08 48 ff c0 49 3b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 0f 48 89 75 17 4c 8b 7d ff 4c 2b fb 41 b9 04 00 00 00 41 b8 00 10 00 00 49 8d ?? ?? 33 c9 ff 15 ?? ?? ?? ?? 4c 8b f0 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 5d ff 48 89 74 24 28 89 74 24 20 4d 8b ce 4c 8d ?? ?? ?? ?? ?? 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b f0 48 89 45 17 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b8 40 00 00 00 8b d0 48 8b cf 8b f0 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 13 44 8b c6 48 8b cf e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

