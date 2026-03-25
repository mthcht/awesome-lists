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

rule TrojanDropper_Win64_Tedy_KKB_2147965478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Tedy.KKB!MTB"
        threat_id = "2147965478"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 95 98 00 00 00 48 8b 45 48 48 01 d0 0f b6 00 83 f0 c4 89 c2 48 8b 4d 30 48 8b 45 48 48 01 c8 88 10 48 83 45 48 01}  //weight: 20, accuracy: High
        $x_5_2 = "\\Microsoft\\Windows\\mspf.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

