rule VirTool_Win64_Gorevesh_A_2147772377_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gorevesh.A!MTB"
        threat_id = "2147772377"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gorevesh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GoReverseShellTLS" ascii //weight: 1
        $x_1_2 = {48 89 4c 24 08 48 c7 44 24 10 03 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 4c 24 18 48 c7 44 24 20 12 00 00 00 48 89 44 24 28 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 8c 24 d8 00 00 00 48 89 84 24 d0 00 00 00 c6 44 24 4f 01 48 8d ?? ?? ?? ?? ?? 48 89 0c 24 48 c7 44 24 08 07 00 00 00 0f 57 c0 0f 11 44 24 10 48 c7 44 24 20 00 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

