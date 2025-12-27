rule Trojan_Win64_RoningLoader_CJ_2147958292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RoningLoader.CJ!MTB"
        threat_id = "2147958292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RoningLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {46 0f b6 0c 01 46 32 0c 13 41 c0 c1 04 46 88 0c 13 44 8d 49}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

