rule HackTool_Win64_EDRSandBlast_SA_2147913213_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/EDRSandBlast.SA!MTB"
        threat_id = "2147913213"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRSandBlast"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 89 45 ?? 8b 45 ?? 89 45 ?? 83 7d ?? ?? 7e ?? 8b 45 ?? 99 83 e0 ?? 33 c2 2b c2 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c2 d1 f8 89 45 ?? 8b 85 ?? ?? ?? ?? ff c0 89 85 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

