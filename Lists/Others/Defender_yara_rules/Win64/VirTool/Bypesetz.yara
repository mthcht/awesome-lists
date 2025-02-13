rule VirTool_Win64_Bypesetz_A_2147914834_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypesetz.A!MTB"
        threat_id = "2147914834"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypesetz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 44 24 40 [0-34] 48 8b cf ?? ?? ?? 48 8b cd ?? ?? ?? ?? ?? ?? 48 8b ce [0-18] 8b d0 [0-73] 44 89 64 24 40 ?? ?? ?? ?? ?? ?? 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 4c 03 18 48 ff c0 41 3a 4c 03 ff ?? ?? ?? ?? ?? ?? 48 83 f8 06 ?? ?? 8b 4b 24 ?? ?? ?? ?? ?? 8b 53 20 ?? ?? ?? ?? 49 03 ce ?? ?? ?? ?? ?? ?? 44 39 64 24 40 ?? ?? 8b 43 24 44 8b 43 20 [0-19] 8b 4b 24 ?? ?? ?? ?? ?? 8b 53 20 49 03 ce 44 8b 44 24 40}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c9 4c 89 64 24 30 44 89 64 24 28 ba 00 00 00 80 49 8b ce c7 44 24 20 03 00 00 00 [0-16] 48 8b f0 48 83 f8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

