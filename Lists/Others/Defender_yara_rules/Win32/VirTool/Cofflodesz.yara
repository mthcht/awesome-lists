rule VirTool_Win32_Cofflodesz_A_2147914833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Cofflodesz.A!MTB"
        threat_id = "2147914833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cofflodesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f0 83 c2 01 89 55 f0 8b 45 dc 0f b7 48 02 39 4d f0 ?? ?? ?? ?? ?? ?? 6b 55 f0 28 8b 45 0c ?? ?? ?? ?? 89 4d e4 8b 55 e4 0f b7 42 20 03 45 c8 89 45 c8 6a 40 68 00 30 10 00 8b 4d e4 8b 51 10 52 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 04 00 00 00 c1 e2 00 8b 45 0c 8b 0c 10 51 ?? ?? ?? ?? ?? 83 c4 14 89 45 e8 83 7d e8 00 [0-18] 83 c4 04 ?? ?? ?? 52 ?? ?? ?? ?? ?? 83 c4 04 89 45 f8 83 7d f8 00 ?? ?? 8b 45 f8 50}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d f8 51 ?? ?? ?? ?? ?? 83 c4 04 89 45 fc 6a 04 ?? ?? ?? 52 8b 45 08 8b 48 04 51 ?? ?? ?? ?? ?? 83 c4 0c 8b 55 08 8b 42 08 83 c0 04 8b 4d 08 89 41 08 8b 55 08 8b 42 04 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

