rule VirTool_Win32_Bypesetz_A_2147914835_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bypesetz.A!MTB"
        threat_id = "2147914835"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bypesetz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 88 c8 50 40 00 40 83 f8 1e ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 c8 50 40 00 ?? ?? ?? ?? ?? ?? 8b d8 83 fb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d f0 68 [0-20] 83 c4 08 57 ?? ?? ?? ff 75 ec 8b 35 10 30 40 00 ?? ?? 53 [0-8] 50 [0-48] 83 c4 10 [0-22] c7 45 f8 00 00 00 00 ?? ?? ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 0c 03 45 f8 6a 40 ff 76 08 50 ?? ?? ?? ?? ?? ?? 83 7d f4 00 ?? ?? ?? ?? ?? ?? 8b 4e 0c 8b 7d f0 ff 76 08 ?? ?? ?? 50 8b 45 f8 03 c1 50 ?? ?? ?? ?? ?? 83 c4 0c ?? ?? ?? 50 ff 75 f4 8b 46 0c ff 76 08 03 45 f8 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

