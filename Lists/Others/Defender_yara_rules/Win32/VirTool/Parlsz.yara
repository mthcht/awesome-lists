rule VirTool_Win32_Parlsz_B_2147844670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Parlsz.B!MTB"
        threat_id = "2147844670"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Parlsz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 ff 74 24 78 c7 84 24 c8 02 00 00 01 00 00 00 89 8c 24 d0 02 00 00 c7 84 24 d4 02 00 00 02 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 60 00 00 00 00 8d ?? ?? ?? 50 6a 00 6a 00 56 8b 35 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 74 24 1c 89 7c 24 6c 57 56 ff 74 24 24 ff}  //weight: 1, accuracy: High
        $x_1_4 = {6a 08 8d 84 ?? ?? ?? ?? ?? 50 6a 00 57 ff 74 24 58 ff b4 24 8c 00 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

