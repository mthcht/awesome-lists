rule Trojan_Win64_Sarupx_RDA_2147842264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sarupx.RDA!MTB"
        threat_id = "2147842264"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sarupx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8d 42 01 44 0f b6 d0 42 0f b6 54 14 60 41 8d 04 11 44 0f b6 c8 42 8a 44 0c 60 42 88 44 14 60 42 88 54 0c 60 42 0f b6 44 14 60 03 c2 99 41 23 d4 03 c2 41 23 c4 2b c2 8a 44 04 60 41 30 00 49 ff c0 49 83 eb 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

