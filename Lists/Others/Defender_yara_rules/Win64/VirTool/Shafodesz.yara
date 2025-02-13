rule VirTool_Win64_Shafodesz_A_2147852613_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shafodesz.A!MTB"
        threat_id = "2147852613"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shafodesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 00 00 00 41 b8 bb 01 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 48 8b 05 10 ea 00 00 ff ?? 48 8b 55 10 48 89 02 48 8b 45 10 48 8b 00 48}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 8d 00 08 00 00 48 89 95 08 08 00 00 48 8d ?? ?? ?? ?? ?? 48 89 85 e0 07 00 00 48 ?? ?? ?? 41 b8 00 08 00 00 ba 00 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 95 e0 07 00 00 48 ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 08 14 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 85 c0 75 14 e8 ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

