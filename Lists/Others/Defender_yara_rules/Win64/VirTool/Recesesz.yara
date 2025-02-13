rule VirTool_Win64_Recesesz_A_2147902289_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Recesesz.A!MTB"
        threat_id = "2147902289"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Recesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 a8 01 00 00 01 48 8b 05 9f 6f 44 00 48 83 f8 02 ?? ?? 48 89 9c 24 f0 09 00 00 [0-32] 48 89 11 ba 01 00 00 00 48 89 51 08 48 83 61 20 00 48 89 84 24 f8 09 00 00 4c 89 ac 24 40 0f 00 00 48 89 71 10 48 89 51 18 ?? ?? ?? ?? ?? ?? ?? ba 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 84 24 00 0a 00 00 49 89 45 10 f3 0f 6f 84 24 f0 09 00 00 f3 41 0f 7f 45 00 48 8b 94 24 48 0f 00 00 48 89 f9 ?? ?? ?? ?? ?? 48 8b 4c 24 38 4c 89 f2 ?? ?? ?? ?? ?? 48 8b 94 24 c8 02 00 00 4c 89 f9 ?? ?? ?? ?? ?? 48 8b 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

