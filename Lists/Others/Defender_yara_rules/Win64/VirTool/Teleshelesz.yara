rule VirTool_Win64_Teleshelesz_A_2147924241_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Teleshelesz.A!MTB"
        threat_id = "2147924241"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Teleshelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 48 8b 05 a5 e2 39 00 ?? ?? 48 89 c2 [0-17] 49 89 c8 48 89 c1 [0-18] 48 89 c1 ?? ?? ?? ?? ?? 83 f0 01 84 c0 ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 89 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 00 00 00 00 ba 01 00 00 00 b9 02 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 98 05 00 00 48 83 bd 98 05 00 00 ff ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d 4f 72 34 00 ?? ?? ?? ?? ?? 48 8b 85 a0 05 00 00 48 89 c1 ?? ?? ?? ?? ?? 48 8b 85 a8 05 00 00 48 89 c1 [0-16] 48 8b 05 9c e1 39 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 98 05 00 00 41 b8 10 00 00 00 48 89 c1 48 8b 05 cb e0 39 00 ?? ?? c1 e8 1f 84 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d 00 71 34 00 ?? ?? ?? ?? ?? 48 8b 85 98 05 00 00 48 89 c1 48 8b 05 96 e0 39 00}  //weight: 1, accuracy: Low
        $x_1_4 = {bb 00 00 00 00 [0-19] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 89 c3 ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c2 48 8b 85 a0 05 00 00 41 89 d8 48 89 c1 ?? ?? ?? ?? ?? 85 c0 0f 9e c0 84 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

