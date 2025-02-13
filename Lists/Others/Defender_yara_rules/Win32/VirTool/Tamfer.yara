rule VirTool_Win32_Tamfer_A_2147818516_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tamfer.A!MTB"
        threat_id = "2147818516"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tamfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 00 00 00 00 00 00 00 00 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {41 56 48 83 ec 40 4c 8b f1 49 8b f1 48 8d ?? ?? ?? ?? ?? 41 8b e8 48 8b fa 33 db ff 15 ?? ?? ?? ?? 48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4c 8b d0 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b d1 b8 ?? 00 00 00 0f 05 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

