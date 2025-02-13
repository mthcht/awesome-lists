rule VirTool_Win64_Evelocresz_A_2147906323_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Evelocresz.A!MTB"
        threat_id = "2147906323"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Evelocresz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 38 [0-19] 48 8b c8 [0-19] 48 89 05 38 1b 02 00 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 01 00 00 00 ?? ?? ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 15 0f 1b 02 00 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 5a 78 48 8b 41 08 48 83 80 f8 00 00 00 03 48 85 db ?? ?? 4d 85 c0 ?? ?? 48 81 7b c8 00 00 02 00 ?? ?? 83 7b d0 44 ?? ?? 48 b8 31 00 33 00 33 00 37 00 49 39 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

