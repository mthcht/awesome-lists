rule VirTool_Win64_Nemangelz_A_2147907202_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nemangelz.A!MTB"
        threat_id = "2147907202"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nemangelz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b a5 e8 d2 00 00 4d 8b 84 24 e8 08 00 00 48 c7 44 24 20 22 00 00 00 [0-20] 48 89 f1 4c 89 ea ?? ?? ?? ?? ?? 48 89 f1 ?? ?? ?? ?? ?? 48 89 c2 49 89 84 24 10 1f 00 00 ?? ?? ?? ?? ?? ?? ?? 49 89 84 24 18 1f 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 84 24 d0 1e 00 00 4d 6b a4 24 e0 1e 00 00 48 ?? ?? ?? ?? ?? ?? ?? 6a 03 5f 4d 85 e4 [0-20] 48 89 85 40 ba 00 00 48 83 c0 30 4c 89 ad 48 ba 00 00 48 89 8d 50 ba 00 00 4c 89 ad 58 ba 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 8d 00 b2 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 8b 84 24 e8 08 00 00 48 c7 44 24 20 25 00 00 00 [0-20] 48 89 f1 4c 89 ea ?? ?? ?? ?? ?? 48 89 f1 ?? ?? ?? ?? ?? 48 89 c2 49 89 84 24 10 1f 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

