rule VirTool_Win64_Cordesesz_A_2147895621_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cordesesz.A!MTB"
        threat_id = "2147895621"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cordesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 45 d0 48 8b 45 18 48 89 45 d8 48 8d ?? ?? ?? ?? ?? 48 89 45 e0 c7 45 e8 ce 00 00 00 48 8b 45 20 48 89 45 f0 48 ?? ?? ?? 48 89 c2 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 b8 48 8b 45 30 48 89 45 c0 48 c7 45 c8 00 00 00 00 c7 45 d0 00 00 00 00 48 c7 45 d8 00 00 00 00 48 c7 45 e0 00 00 00 00 48 c7 45 e8 00 00 00 00 48 c7 45 f0 00 00 00 00 48 ?? ?? ?? 48 89 c2 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 45 f8 ff ff ff ff 48 8d ?? ?? ?? ?? ?? 48 89 c2 48 8b 05 48 cf 0e 00 48 89 c1 e8 ?? ?? ?? ?? 48 89 c1 48 8b 05 46 cf 0e 00 48 89 c2 e8 ?? ?? ?? ?? 48 8b 45 f8 48 89 c1 e8 ?? ?? ?? ?? 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

