rule VirTool_Win64_Bypatchsz_A_2147916122_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypatchsz.A!MTB"
        threat_id = "2147916122"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypatchsz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 56 53 48 83 ec 30 48 89 cb [0-19] 48 85 c0 ?? ?? ?? ?? ?? ?? 48 89 da 48 89 c1 ?? ?? ?? ?? ?? ?? 48 85 c0 48 89 c3 [0-18] 41 b8 40 00 00 00 ba 03 00 00 00 48 8b 35 29 b8 14 00 49 89 f9 48 89 c1 ?? ?? 85 c0 ?? ?? b8 33 c0 ff ff c6 43 02 c3 49 89 f9 48 89 d9 66 89 03 ba 03 00 00 00 ?? ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {49 3b 66 10 ?? ?? 55 48 89 e5 48 83 ec 20 48 89 44 24 30 48 89 c3 31 c9 31 ff [0-18] 48 8b 54 24 30 48 89 14 24 ?? ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 51 55 14 00 65 4d 8b 36 4d 8b 36 8b 44 24 08 48 83 c4 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

