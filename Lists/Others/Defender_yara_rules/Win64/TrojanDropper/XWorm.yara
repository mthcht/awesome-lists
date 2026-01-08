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

