rule VirTool_Win64_Beresez_A_2147921772_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Beresez.A!MTB"
        threat_id = "2147921772"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Beresez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 89 d0 48 89 8c 24 58 06 00 00 89 84 24 60 06 00 00 ?? ?? 0f 10 84 24 ?? 04 00 00 0f 29 84 24 80 04 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 89 d0 48 89 8c 24 58 06 00 00 89 84 24 60 06 00 00 ?? ?? 0f 10 84 24 e8 01 00 00 0f 29 84 24 d0 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 84 24 00 04 00 00 48 89 84 24 f8 05 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 78 06 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 80 06 00 00 48 8b 84 24 78 06 00 00 48 89 84 24 48 06 00 00 48 8b 84 24 80 06 00 00 48 89 84 24 50 06 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "namedpipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

