rule VirTool_Win32_Pringetesz_A_2147901807_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Pringetesz.A!MTB"
        threat_id = "2147901807"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pringetesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 30 33 40 00 ?? ?? ?? ?? ?? 8b 35 04 30 40 00 83 c4 04 68 54 33 40 00 53 ?? ?? 68 64 33 40 00 53 ?? ?? 68 74 33 40 00 53 8b f8 ?? ?? 68 8c 33 40 00 53 89 44 24 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 ff 74 24 10 68 fc 33 40 00 ?? ?? ?? ?? ?? 83 c4 08 ?? ?? ?? ?? 50 ?? ?? ?? ?? 50 68 ff ff 1f 00 ?? ?? ?? ?? 50 ?? ?? a3 74 53 40 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 74 24 28 68 c0 34 40 00 ?? ?? ?? ?? ?? 83 c4 08 ?? ?? ?? ?? 6a 00 68 cd 01 00 00 50 ff 74 24 34 ff 74 24 34 ?? ?? ?? ?? a3 74 53 40 00 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

