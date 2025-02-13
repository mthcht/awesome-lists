rule HackTool_Win64_MimikatzPacker_SA_2147889460_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/MimikatzPacker.SA!MTB"
        threat_id = "2147889460"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MimikatzPacker"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b cf e8 ?? ?? ?? ?? 85 c0 74 ?? 0f b7 44 2e ?? 48 83 c7 ?? ff c3 3b d8 76}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 ?? 75 ?? 48 83 ef ?? 0f 29 84 24 ?? ?? ?? ?? 48 83 ee ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

