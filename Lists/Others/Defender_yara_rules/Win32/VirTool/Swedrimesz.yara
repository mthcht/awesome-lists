rule VirTool_Win32_Swedrimesz_A_2147852611_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Swedrimesz.A!MTB"
        threat_id = "2147852611"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Swedrimesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 18 8b 4c 24 1c e8 ?? ?? ?? ?? 8d ?? ?? 89 44 24 24 33 f6 83 c4 04 83 7c 24 0c 02 8b fa 89 7c 24 1c 0f 45 f1 89 74 24 0c 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 56 ff 15 ?? ?? ?? ?? 50 68 70 47 40 00 e8 d4 ?? ?? ?? 83 c4 08 85 f6 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5c 24 20 57 53 56 e8 26 ?? ?? ?? 83 c4 0c 57 6a 00 53 e8 b5 ?? ?? ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

