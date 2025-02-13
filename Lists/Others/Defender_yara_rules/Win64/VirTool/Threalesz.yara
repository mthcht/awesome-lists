rule VirTool_Win64_Threalesz_A_2147921774_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Threalesz.A!MTB"
        threat_id = "2147921774"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Threalesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 00 05 00 00 48 89 c1 48 8b 05 7a 7a 00 00 ?? ?? ?? ?? ?? ?? 48 8b 8d 00 05 00 00 48 89 c2 48 8b 05 cb 79 00 00 ?? ?? ?? ?? ?? ?? 48 8b 95 e8 04 00 00 48 89 10 ?? ?? ?? ?? 48 83 c0 08 48 8b 15 cc 79 00 00 48 89 10 ?? ?? ?? ?? 48 83 c0 10 48 8b 15 4a 79 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 f8 04 00 00 48 c7 44 24 20 00 00 00 00 41 b9 18 00 00 00 49 89 d0 48 89 ca 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c0 [0-25] 48 8b 95 e8 04 00 00 48 8b 85 f8 04 00 00 41 b9 00 80 00 00 41 b8 00 00 00 00 48 89 c1 [0-48] 48 8b 8d 00 05 00 00 48 89 c2}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 95 e8 04 00 00 48 8b 85 f8 04 00 00 41 b9 00 80 00 00 41 b8 00 00 00 00 48 89 c1 [0-35] b9 d0 07 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 85 00 05 00 00 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

