rule VirTool_Win64_Semegentesz_A_2147913711_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Semegentesz.A!MTB"
        threat_id = "2147913711"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Semegentesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 18 00 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 68 00 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? c7 45 d0 68 00 00 00 8b 45 0c 80 cc 01 89 45 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ba 00 00 00 00 b9 00 00 00 00 [0-18] 48 89 85 70 06 00 00 48 8b 85 70 06 00 00 48 c7 [0-25] 8b 48 0c ?? ?? ?? ?? ?? ?? ?? 8b 50 08 ?? ?? ?? ?? ?? ?? ?? 8b 40 04 41 89 c8 89 c1 ?? ?? ?? 48 8b 95 70 06 00 00 48 89 02}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 88 02 00 00 0f b6 40 10 84 c0 ?? ?? 48 8b 85 88 02 00 00 0f b6 40 04 0f b6 c0 83 f8 05 ?? ?? ?? ?? ?? ?? 83 f8 05 ?? ?? ?? ?? ?? ?? 83 f8 04 ?? ?? ?? ?? ?? ?? 83 f8 04 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 88 02 00 00 48 8b 40 18 48 89 85 40 02 00 00 48 8b 85 40 02 00 00 48 8b 00 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 8b 85 40 02 00 00 48 8b 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 80 48 89 c1 48 8b 05 8f 26 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

