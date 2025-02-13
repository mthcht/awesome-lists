rule VirTool_Win64_Radkt_A_2147910497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Radkt.A!MTB"
        threat_id = "2147910497"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Radkt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 20 [0-20] 85 c0 ?? ?? 8b d0 [0-23] 48 8b 4c 24 38 [0-23] 48 8b 01 ?? ?? ?? 85 c0 ?? ?? 8b d0 [0-23] 8b 44 24 40 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 74 24 30 85 c0 ?? ?? ?? ?? ?? ?? 8b f8 48 8b 4b e8 ?? ?? ?? ?? ?? ?? 48 8b 4b f0 ?? ?? ?? ?? ?? ?? 48 8b 0b [0-16] 48 83 ef 01 ?? ?? 48 8b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

