rule VirTool_Win64_Stedebypesz_A_2147921761_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Stedebypesz.A!MTB"
        threat_id = "2147921761"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Stedebypesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 05 24 6c 00 00 48 89 85 b0 01 00 00 48 8b 05 be 2e 00 00 48 89 85 a8 01 00 00 48 8b 05 00 6c 00 00 48 89 85 a0 01 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 85 98 01 00 00 48 8b 05 a4 2e 00 00 48 89 85 ?? 01 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 85 88 01 00 00 c6 85 77 01 00 00 00 c7 85 bc 01 00 00 00 00 00 00 ?? 48 8b 85 88 01 00 00 4c 8b 85 b0 01 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 fa 89 02 48 83 c2 04 [0-16] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 89 c0 ?? ?? ?? ?? ?? ?? ?? 48 89 c2 48 c7 c1 01 00 00 80 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 b8 8b 95 d8 01 00 00 89 54 24 28 ?? ?? ?? ?? 48 89 54 24 20 41 b9 01 00 00 00 41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 45 b8 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

