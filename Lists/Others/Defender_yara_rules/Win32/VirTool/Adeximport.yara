rule VirTool_Win32_Adeximport_A_2147828024_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Adeximport.A!MTB"
        threat_id = "2147828024"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Adeximport"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 ac 02 00 00 89 d0 c1 e0 02 01 d0 c1 e0 02 89 85 44 02 00 00 8b 85 44 02 00 00 83 c0 28 89 85 40 02 00 00 8b 85 40 02 00 00 48 89 c1 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 95 b8 02 00 00 48 8b 85 58 02 00 00 48 01 d0 48 89 85 60 02 00 00 48 8b 85 60 02 00 00 8b 40 0c}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 85 c0 02 00 00 48 83 c0 08 8b 08 48 8b 85 28 02 00 00 48 8b 95 78 02 00 00 41 89 c8 48 89 c1 e8}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 20 2b 45 28 89 c1 8b 55 28 48 8b 45 18 48 01 c2 4c 8d ?? ?? 48 8b 45 f0 48 c7 44 24 20 00 00 00 00 4d 89 c1 41 89 c8 48 89 c1 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

