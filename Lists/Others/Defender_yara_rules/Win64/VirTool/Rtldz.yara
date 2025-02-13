rule VirTool_Win64_Rtldz_A_2147841304_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rtldz.A!MTB"
        threat_id = "2147841304"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rtldz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b d4 41 8b ce e8 ?? ?? ?? ?? 48 8b f0 48 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {48 03 4b 08 48 8d ?? ?? 41 b8 20 00 00 00 e8 ?? ?? ?? ?? 83 43 10 20}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 01 ff c7 48 8b c8 48 85 c0 75}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 45 80 48 8d ?? ?? ?? 48 89 44 24 68 48 8d ?? ?? 48 89 44 24 78 48 89 74 24 60 44 89 6c 24 70 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

