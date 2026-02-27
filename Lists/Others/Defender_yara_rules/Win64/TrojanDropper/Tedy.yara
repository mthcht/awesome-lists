rule TrojanDropper_Win64_Tedy_ARA_2147963821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Tedy.ARA!MTB"
        threat_id = "2147963821"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b c2 83 e0 1f 0f b6 44 ?? ?? ?? 32 04 ?? 88 01 48 ff c2 48 3b d3 72 e3}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b c1 83 e0 1f 0f b6 44 04 60 32 04 0e 88 04 0f 48 ff c1 48 3b cb 72 e7}  //weight: 2, accuracy: High
        $x_3_3 = "nvd_%08X.dll" ascii //weight: 3
        $x_3_4 = "NVDisplayContainer.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

