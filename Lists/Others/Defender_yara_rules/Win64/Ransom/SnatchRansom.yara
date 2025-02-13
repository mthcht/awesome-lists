rule Ransom_Win64_SnatchRansom_YAA_2147891733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SnatchRansom.YAA!MTB"
        threat_id = "2147891733"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SnatchRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 8d 14 92 c1 e2 02 41 29 d1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08}  //weight: 2, accuracy: Low
        $x_3_2 = {41 bb fd 9e 5f 22 41 29 f3 49 83 c3 01 41 ba ?? ?? ?? ?? 41 89 c9 89 c8 41 f7 ea}  //weight: 3, accuracy: Low
        $x_2_3 = {41 89 c9 89 c8 41 f7 ea 42 8d 04 0a c1 f8 05 89 cb c1 fb 1f 29 d8 6b c0 3e 41 29 c1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_SnatchRansom_YAB_2147891734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SnatchRansom.YAB!MTB"
        threat_id = "2147891734"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SnatchRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.VDMOperationStarted" ascii //weight: 1
        $x_1_2 = "crypto/rand/rand.go" ascii //weight: 1
        $x_1_3 = "main.Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_4 = "Go build ID:" ascii //weight: 1
        $x_1_5 = {48 8d 15 15 c4 29 00 89 04 8a 48 8d 41 01 48 3d 00 01 00 00 7d 0a 48 89 c1 c1 e0 18 31 d2 eb 04 c3 48 ff c2 48 83 fa 08 7d d6 0f ba e0 1f 73 09 d1 e0 35 b7 1d c1 04 eb e8 d1 e0 90 eb e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

