rule VirTool_Win32_Excheposez_A_2147907208_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Excheposez.A!MTB"
        threat_id = "2147907208"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Excheposez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 00 00 00 00 33 c0 0f 11 45 d0 c7 45 e0 00 00 00 00 c7 45 e4 07 00 00 00 66 89 45 d0 ?? ?? ?? c6 45 fc 01 50 ?? ?? ?? 50 6a 01 6a 00 ?? ?? ?? ?? ?? ?? 33 f6 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 01 00 00 50 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 68 00 01 00 00 ?? ?? ?? ?? ?? ?? 6a 00 50 ?? ?? ?? ?? ?? 83 c4 18 c7 85 d0 bd ff ff 00 00 00 00 6a 03 [0-18] 50 6a 01 68 ff 01 0f 00 ?? ?? ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

