rule VirTool_Win64_Bumblerz_A_2147838737_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bumblerz.A!MTB"
        threat_id = "2147838737"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bumblerz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 05 61 3a 01 00 48 89 44 24 20 4c 8d ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 73}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 08 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 4d 08 e8 ?? ?? ?? ?? ba 04 00 00 00 48 8b c8 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 4c 24 08 57 48 83 ec 20 33 d2 48 8b 4c 24 30 e8 ?? ?? ?? ?? 48 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 c8 01 00 00 48 8b 40 18 48 8b 8d c0 01 00 00 48 2b c8 48 8b c1 48 89 45 08}  //weight: 1, accuracy: High
        $x_1_5 = {48 c7 45 68 00 00 00 00 8b 05 4a 3c 01 00 48 89 85 88 00 00 00 48 8b 85 88 00 00 00 48 c1 e0 02 89 85 a8 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8b f8 33 c0 b9 04 00 00 00 f3 aa 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 40 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {48 8b 45 68 48 39 45 48 0f 83 e4 00 00 00 8b 45 04 ff c0 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 89 45 04 48 63 45 04 48 8b 8d 80 01 00 00 0f b6 04 01 8b 4d 24 03 c8 8b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

