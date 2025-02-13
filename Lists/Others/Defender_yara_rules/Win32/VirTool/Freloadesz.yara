rule VirTool_Win32_Freloadesz_A_2147918046_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Freloadesz.A!MTB"
        threat_id = "2147918046"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Freloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 30 0a 40 3d 6e 61 40 00 ?? ?? 8b 75 d0 8b 7d cc 6a 00 68 16 01 00 00 68 58 60 40 00 56 57 ?? ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 6a 00 6a 00 57}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 18 0f 57 c0 8b 45 14 03 d1 8b ca 66 0f d6 45 e0 48 c1 e9 02 23 c8 c7 45 e8 00 00 00 00 8b 45 10 83 e2 03 6a 1c 0f 11 45 d0 8b 04 88 ?? ?? ?? 51 6a 00 8b 04 ?? 50 89 45 c4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 10 83 e2 03 8b 04 88 8b 3c ?? 57 89 7d b8 ?? ?? ?? ?? ?? ?? 89 45 c8 ?? ?? ?? 50 6a 40 68 16 01 00 00 56 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

