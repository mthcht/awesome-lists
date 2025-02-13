rule VirTool_Win64_Plebledesz_A_2147890410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Plebledesz.A!MTB"
        threat_id = "2147890410"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Plebledesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 10 44 0f 11 78 08 48 c7 40 18 02 00 00 00 44 0f 11 78 20 48 8b 54 24 30 48 89 50 30 48 8b ?? ?? ?? ?? ?? 48 89 c3 b9 07 00 00 00 48 89 cf 48 89 d0 e8 ?? ?? ?? ?? 0f 1f 40 00 48 83}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 7c 24 28 48 89 74 24 58 48 39 f9 ?? ?? 48 89 ca 48 29 f9 0f 1f 44 00 00 48 39 ca 0f 82 ?? ?? ?? ?? 49}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 6c 24 38 48 ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 48 85 db ?? ?? bb 28 00 00 00 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 44 0f 11 7c 24 28 48 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 8c 24 80 01 00 00 48 89 84 24 88 01 00 00 48 8d 8c ?? ?? ?? ?? ?? 48 89 4c 24 40 48 8d ?? ?? ?? e8 53 ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b 0d 05 60 1d 00 48 8b 3d 06 60 1d 00 48 8b 84 24 50 01 00 00 e8 ?? ?? ?? ?? 48 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

