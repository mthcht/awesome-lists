rule VirTool_Win64_Bedobesz_A_2147921768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bedobesz.A!MTB"
        threat_id = "2147921768"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bedobesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 53 48 83 ec 58 ?? ?? ?? ?? ?? ?? ?? ?? c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 [0-18] 48 89 45 c8 48 8b 05 24 d6 00 00 48 8b 50 18 48 8b 45 c8 41 b9 00 00 00 00 41 b8 5c 11 00 00 48 89 c1 ?? ?? ?? ?? ?? 48 89 45 c0 48 83 7d c0 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 45 b8 00 00 00 00 c7 45 b4 00 00 00 00 48 8b 05 e3 d5 00 00 48 8b 50 28 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 c0 4d 89 c1 49 89 c8 48 89 c1 ?? ?? ?? ?? ?? 85 c0 0f 94 c0 84 c0 ?? ?? 8b 4d b4 48 8b 55 b8 48 8b 05 ae d5 00 00 41 89 c8 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 48 83 ec 30 [0-18] 48 89 45 f8 ?? ?? ?? ?? ?? 48 89 05 09 d5 00 00 ?? ?? ?? ?? 48 89 c2 b9 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

