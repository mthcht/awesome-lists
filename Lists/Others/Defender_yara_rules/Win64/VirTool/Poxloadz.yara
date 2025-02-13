rule VirTool_Win64_Poxloadz_A_2147844667_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Poxloadz.A!MTB"
        threat_id = "2147844667"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Poxloadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 e0 48 8d ?? ?? 4c 8b 55 f8 41 b9 00 00 00 00 49 89 d0 48 8b ?? ?? ?? ?? ?? 48 89 c1 41}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 00 10 00 00 48 c7 c1 ff ff ff ff 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 48 8d ?? ?? ?? ?? ?? 48 89 c2 48 8b ?? ?? ?? ?? ?? ff ?? 48 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 d1 48 31 d2 e8 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

