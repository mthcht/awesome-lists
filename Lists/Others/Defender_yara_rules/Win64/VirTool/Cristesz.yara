rule VirTool_Win64_Cristesz_A_2147900979_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cristesz.A!MTB"
        threat_id = "2147900979"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cristesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 48 89 44 24 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 45 33 c0 48 89 44 24 40 33 c9 48 89 7c 24 38 4c 89 74 24 30 c7 44 24 28 20 00 00 00 44 89 74 24 20 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 5c 24 60 4c 8b c3 ?? ?? ?? ?? ?? ?? ?? ba 02 ?? ?? ?? e8 ?? ?? ?? ?? 33 d2 c7 44 24 20 04 00 00 00 41 b9 00 30 00 00 41 b8 00 ?? ?? ?? 48 8b cb ff ?? ?? ?? ?? ?? 48 8b f8}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b9 00 04 00 00 4d 8b c7 48 89 44 24 20 48 8b d7 48 8b cb ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 81 7c 24 50 00 04 00 00 ?? ?? 4c 8b 4e 08}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8b cf 48 89 44 24 30 45 33 c0 44 89 74 24 28 33 d2 48 8b cb 4c 89 74 24 20 ff ?? ?? ?? ?? ?? 48 8b f8}  //weight: 1, accuracy: Low
        $x_1_5 = {44 8b c0 e8 ?? ?? ?? ?? 48 8b 4e 10 e8 ?? ?? ?? ?? 48 8b 4e 08 4c 8b f0 e8 ?? ?? ?? ?? 4c 8b c0 ?? ?? ?? ?? ?? ?? ?? 8b d7 48 8b d8 e8 ?? ?? ?? ?? 4d 8b c6 ?? ?? ?? ?? ?? ?? ?? 8b d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

