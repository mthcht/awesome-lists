rule VirTool_Win64_Proholz_A_2147847729_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Proholz.A!MTB"
        threat_id = "2147847729"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Proholz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 44 05 00 00 48 63 d0 48 8b 85 a0 04 00 00 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 48 8b 05 34 cb 00 00 ff ?? 48 89 85 30 05 00 00 48 83 bd 30 05 00 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 4d 20 48 89 55 28 4c 89 45 30 4c 89 4d 38 48 ?? ?? ?? 48 89 45 f0 48 8b 5d f0 b9 01 00 00 00 48 8b 05 6d 7b 00 00 ff ?? 48}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 e8 ?? ?? ?? ?? b9 12 00 00 00 48 8b 05 e0 c9 00 00 ff ?? 48 8b 85 a8 04 00 00 48 89 c1 48 8b 05 b5 c9 00 00 ff ?? 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

