rule VirTool_Win32_Threqesz_A_2147908298_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Threqesz.A!MTB"
        threat_id = "2147908298"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Threqesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 85 f6 ?? ?? ?? ?? ?? ?? 8b 3d 18 20 40 00 ?? ?? ?? ?? ?? 56 ?? ?? a3 74 43 40 00 85 c0 [0-17] 56 ?? ?? 83 3d 74 43 40 00 00 a3 78 43 40 00 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 e4 00 00 00 b9 39 00 00 00 ?? ?? ?? ?? ?? ?? be c0 21 40 00 f3 a5 6a 00 ?? ?? ?? ?? ?? ?? 8b f8 89 bd ec f7 ff ff 85 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b e5 5d c3 57 [0-16] 83 c4 08 ?? ?? ?? ?? ?? ?? b9 39 00 00 00 f3 a5 ?? ?? ?? ?? ?? ?? 68 28 23 40 00 8b f0 ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

