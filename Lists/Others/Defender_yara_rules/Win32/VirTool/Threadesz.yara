rule VirTool_Win32_Threadesz_A_2147853081_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Threadesz.A!MTB"
        threat_id = "2147853081"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Threadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 20 83 c4 0c 8b d6 57 53 8b 5c 24 24 53 ff 74 24 2c e8 ?? ?? ?? ?? 83 c4 10 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 d4 85 c0 0f 84 eb 00 00 00 53 53 53 53 53 53 50 ff 15 ?? ?? ?? ?? 89 45 d0 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 38 8d ?? ?? 50 57 53 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b fa 89 45 a0 8d ?? ?? 0f 11 45 c4 66 c7 45 d4 48 b9 c7 45 de 48 89 08 48 c7 45 e2 83 ec 40 e8 c7 45 e6 11 00 00 00 c6 45 ea 48 c7 45 ef 5b 41 5a 41 c7 45 f3 59 41 58 5a c7 45 f7 59 58 ff e0 c6 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

