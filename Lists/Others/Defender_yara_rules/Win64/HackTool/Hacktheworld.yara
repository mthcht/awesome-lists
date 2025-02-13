rule HackTool_Win64_Hacktheworld_G_2147742379_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Hacktheworld.G!MTB"
        threat_id = "2147742379"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hacktheworld"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 0a b8 00 00 00 00 e9 ?? 01 00 00 e8 (40|2d|44) ff ff ff 85 c0 0f 84 ?? 01 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 00 e1 f5 05 e8 ?? 16 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {76 a4 41 b9 40 00 00 00 41 b8 00 10 00 00 ba ?? ?? ?? 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? 00 ff d0 [0-153] 41 b9 00 00 00 00 49 89 c0 ba 00 00 00 00 b9 00 00 00 00 48 8b 05 ?? ?? ?? 00 ff d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

