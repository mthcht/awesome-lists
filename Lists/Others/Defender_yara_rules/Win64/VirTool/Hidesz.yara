rule VirTool_Win64_Hidesz_A_2147849229_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hidesz.A!MTB"
        threat_id = "2147849229"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hidesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c7 f3 a4 4c 89 ee 48 8b 44 24 58 48 63 4c 24 54 48 8b 40 10 48 89 c7 f3 a4 48 8b 44 24 58 4c 8b 6d 00 48 8d ?? ?? ?? ?? ?? 48 89 18 48 8d ?? ?? ?? ?? ?? e8 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 0e 48 89 c2 e8 ea ?? ?? ?? 85 c0 0f 84 fb 05 00 00 49 8b 0e 49 8b 56 20 4c 8d ?? ?? ?? ?? ?? 49 ?? ?? ?? e8 03}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b 06 45 31 ff 49 8b 4e 10 45 31 c9 4c 89 7c 24 28 45 31 c0 31 d2 c7 44 24 20 00 00 00 10 ff ?? ?? ?? ?? ?? 49 89 46 38 48 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 fa 48 89 c6 49 8b 06 48 89 f1 ff ?? ?? ?? ?? ?? 49 8b 06 48 8b 54 24 68 48 89 f9 ff ?? ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

