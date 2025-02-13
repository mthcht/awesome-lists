rule VirTool_Win64_Beneloadesz_A_2147914836_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Beneloadesz.A!MTB"
        threat_id = "2147914836"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Beneloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 7c 24 20 [0-24] 85 c0 ?? ?? 3d 53 03 00 c0 ?? ?? 4c 39 74 24 30 [0-17] 85 c0 ?? ?? ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 14 01 00 00 69 00 6e 00 66 44 89 bd 18 01 00 00 ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 4c 8b 4c 24 48 ?? ?? ?? ?? 4c 8b 44 24 50 48 8b 54 24 40 ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b c3 33 d2 48 8b c8 [0-33] 85 c0 ?? ?? ?? ?? ?? ?? 0f b7 5d 70 0f b7 cb 4c 89 7c 24 38 4c 89 7c 24 30 ?? ?? ?? ?? ?? 41 b9 08 00 00 00 4c 89 7c 24 20 [0-19] 85 c0 ?? ?? 4c 39 74 24 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

