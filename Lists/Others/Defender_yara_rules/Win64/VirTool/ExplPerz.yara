rule VirTool_Win64_ExplPerz_A_2147839554_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ExplPerz.A!MTB"
        threat_id = "2147839554"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ExplPerz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 74 00 00 00 00 48 8d ?? ?? 48 8b 8d 38 01 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 14}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 44 0f b7 85 a0 04 00 00 48 8b 95 98 04 00 00 48 8b 8d f8 00 00 00 ff 15 ?? ?? ?? ?? 48 89 85 18 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 45 38 48 c7 45 48 00 00 00 00 48 c7 45 50 00 00 00 00 c7 44 24 50 00 00 00 00 48 c7 44 24 48 00 00 00 00 c7 44 24 40 20 00 00 00 c7 44 24 38 05 00 00 00 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? 4c 8d ?? ?? ba 16 01 12 00 48 8d ?? ?? ?? ?? ?? e8 95 bd ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 44 24 28 48 8d ?? ?? 48 89 44 24 20 45 33 c9 45 33 c0 33 d2 48 8b 8d d8 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {41 b8 04 01 00 00 33 d2 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

