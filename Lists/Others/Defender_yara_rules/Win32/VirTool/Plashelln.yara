rule VirTool_Win32_Plashelln_B_2147844674_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Plashelln.B!MTB"
        threat_id = "2147844674"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Plashelln"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 10 00 00 8b 45 f8 8b 48 08 51 8b 55 08 52 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b f4 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b 4d f8 8b 49 08 83 c1 01 33 d2 f7 f1 8b 45 f8 89 50 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 10 50 8b 4d 0c 51 8b 55 08 8b 42 0c 8b 4d 08 03 41 04 50 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 8b 48 0c 8b 55 08 03 4a 04 89 4d e8 8b f4 6a 00 6a 00 6a 00 8b 45 e8 50 6a 00 6a 00 ff}  //weight: 1, accuracy: High
        $x_1_5 = {8b fc ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3b f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

