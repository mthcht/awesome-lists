rule VirTool_Win32_Temeresz_A_2147890412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Temeresz.A!MTB"
        threat_id = "2147890412"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Temeresz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 53 56 57 68 3c 32 40 00 e8 ?? ?? ?? ?? 68 5c 32 40 00 e8 ?? ?? ?? ?? 83 c4 08 6a 00 6a 00 68 10 11 40 00 6a 0d ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {81 3d 80 43 40 00 a2 00 00 00 57 ?? ?? 81 fe a5 00 00 00 ?? ?? 68 84 31 40 00 e8 ?? ?? ?? ?? 83 c4 04 c7 45 0c 00 00 00 00 6a 10 ff 15 ?? ?? ?? ?? 0f b7 f8 8d ?? ?? c1 ef 0f 83 e7}  //weight: 1, accuracy: Low
        $x_1_3 = {85 ff 74 2d ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8d ?? ?? 51 50 ff 15 ?? ?? ?? ?? 33 c0 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

