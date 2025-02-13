rule VirTool_Win64_Callidus_A_2147905429_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Callidus.A"
        threat_id = "2147905429"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Callidus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 5c 24 10 48 89 74 24 18 48 89 7c 24 20 41 57 48 83 ec 50 ?? ?? ?? ?? ?? ?? ?? 48 33 c4 48 89 44 24 40 48 8b d9 33 c0 48 89 44 24 20 48 89 44 24 30 48 c7 44 24 38 0f 00 00 00 88 44 24 20 ?? ?? ?? ?? ?? ?? ?? 49 c7 c0 ff ff ff ff 66}  //weight: 10, accuracy: Low
        $x_1_2 = "OneNoteC2.dll" ascii //weight: 1
        $x_1_3 = "OutlookC2.dll" ascii //weight: 1
        $x_1_4 = "TeamsC2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

