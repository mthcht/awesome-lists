rule VirTool_Win64_Contenesz_A_2147918050_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Contenesz.A!MTB"
        threat_id = "2147918050"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Contenesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 85 c8 01 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? c7 44 24 20 00 00 00 00 [0-20] ba 01 00 00 00 48 8b c8 [0-23] 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 c0 48 8b c8 ?? ?? ?? ?? ?? ?? 48 89 85 e8 01 00 00 48 83 bd e8 01 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c8 e8 ?? ?? ?? ?? c7 85 84 11 00 00 ff ff ff ff [0-34] 8b 85 84 11 00 00 [0-36] 48 89 85 18 12 00 00 41 b8 18 10 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 4c 24 08 48 89 54 24 10 55 57 48 83 ec 48 ?? ?? ?? ?? 48 8b 85 68 01 00 00 48 8b 00 48 8b 8d 68 01 00 00 ?? ?? ?? 48 8b d0 [0-25] 48 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

