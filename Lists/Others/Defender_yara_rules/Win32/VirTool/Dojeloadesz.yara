rule VirTool_Win32_Dojeloadesz_A_2147917409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dojeloadesz.A!MTB"
        threat_id = "2147917409"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dojeloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 e4 f8 51 53 56 57 ff 75 08 [0-16] ff 35 ec 65 40 00 a1 e8 65 40 00 6a 00 50 50 [0-16] 8b 3d e8 65 40 00 83 c4 1c 8b 35 f4 65 40 00 57 ff 35 ec 65 40 00 56 ?? ?? ?? ?? ?? 83 c4 0c 8b c6 99 6a 00 57 52 50 [0-16] 8b 3d e8 65 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 e4 f8 83 ec 0c a1 00 60 40 00 33 c4 89 44 24 08 53 56 57 ff 75 08 [0-16] a1 f8 65 40 00 6a 00 ff 35 fc 65 40 00 99 52 50 [0-16] 83 c4 1c ?? ?? ?? ?? 50 6a 04 ff 35 fc 65 40 00 ff 35 f8 65 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 83 e4 f8 51 53 8b 5d 08 56 57 53 [0-16] 8b 7d 04 57 [0-16] a1 54 65 40 00 8b 00 99 52 50 a1 e8 65 40 00 6a 00 50 50}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 ff 75 08 [0-22] a1 ec 65 40 00 83 c4 04 99 52 50 [0-16] 83 c4 0c 6a 40 68 00 30 00 00 ff 35 e8 65 40 00 ff 35 ec 65 40 00 ff 15 08 40 40 00 89 44 24 0c 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

