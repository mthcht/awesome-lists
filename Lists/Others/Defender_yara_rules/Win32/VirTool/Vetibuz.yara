rule VirTool_Win32_Vetibuz_A_2147833349_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vetibuz.A!MTB"
        threat_id = "2147833349"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vetibuz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 10 00 00 68 a0 86 01 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 89 8d ?? c8 ff ff [0-5] 85 c9 [0-2] 8d 85 ?? c8 ff ff 50 68 a0 86 01 00 56 53 [0-2] 85 c0 [0-2] 8b 8d ?? c8 ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "virus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vetibuz_B_2147833350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vetibuz.B!MTB"
        threat_id = "2147833350"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vetibuz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 10 00 00 68 a0 86 01 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 89 8d ?? c8 ff ff [0-5] 85 c9 [0-2] 8d 85 ?? c8 ff ff 50 68 a0 86 01 00 56 53 [0-2] 85 c0 [0-2] 8b 8d ?? c8 ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {61 70 69 2e [0-5] 67 69 74 68 [0-3] 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

