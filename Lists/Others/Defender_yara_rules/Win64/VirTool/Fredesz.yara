rule VirTool_Win64_Fredesz_A_2147953323_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Fredesz.A!MTB"
        threat_id = "2147953323"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Fredesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 01 00 00 00 48 89 44 24 70 48 89 44 24 30 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 ?? ?? ?? ?? ?? 45 33 c0 ba 00 00 00 40 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 46 10 48 8b c8 [0-18] 48 8b c8 ?? ?? ?? ?? ?? 48 8b d3 48 83 7b 18 07 ?? ?? 48 8b 13 4c 8b 43 10 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 57 c9 f3 0f 7f 4d 80 [0-19] 8b d8 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

