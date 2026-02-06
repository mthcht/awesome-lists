rule TrojanDropper_Win64_XWorm_AHC_2147960743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XWorm.AHC!MTB"
        threat_id = "2147960743"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b 4d eb 2a c8 88 4d e7 33 c0 66 66 0f 1f 84 00 00 00 00 00 0f b6 4d e7 30 4c 05 0f 48 ff c0 48 83 f8 ?? 72}  //weight: 30, accuracy: Low
        $x_20_2 = "%s%llx.tmp" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_XWorm_AHD_2147960945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XWorm.AHD!MTB"
        threat_id = "2147960945"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 89 7d e7 41 8b c7 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 8b 4d e7 30 4c 05 0f 48 ff c0 48 83 f8 ?? 72}  //weight: 30, accuracy: Low
        $x_20_2 = "%s%llx.tmp" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_XWorm_ARAX_2147962577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XWorm.ARAX!MTB"
        threat_id = "2147962577"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 c0 01 99 c1 ea 18 01 d0 0f b6 c0 29 d0 4c 63 c8 42 0f b6 14 0c 89 d1 44 01 d2 41 89 d0 41 c1 f8 1f 41 c1 e8 18 44 01 c2 0f b6 d2 44 29 c2 41 89 d2 48 63 d2 44 0f b6 04 14 46 88 04 0c 88 0c 14 42 02 0c 0c 0f b6 c9 0f b6 14 0c 30 13 48 83 c3 01 48 39 de 75 a9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

