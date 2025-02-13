rule VirTool_Win32_CoffLdz_B_2147839559_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CoffLdz.B!MTB"
        threat_id = "2147839559"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CoffLdz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f4 8d 85 ?? ?? ?? ?? 50 6a 20 8b 8d 6c ff ff ff 51 8b 95 7c ff ff ff 52 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f4 6a 04 68 00 30 10 00 8b 45 ac b9 08 00 00 00 f7 e1 50 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 89 45 c4 83 7d c4 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 52 8b 45 14 50 8b 4d 10 51 8b 55 0c 52 e8}  //weight: 1, accuracy: High
        $x_1_4 = {a1 58 d2 41 00 89 45 f8 8b 45 08 8b 0d 5c d2 41 00 89 08 c7 05 58 d2 41 00 00 00 00 00 c7 05 5c d2 41 00 00 00 00 00 c7 05 60 d2 41 00 00 00 00 00 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 f8 0f b7 48 02 39 4d ec 73 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

